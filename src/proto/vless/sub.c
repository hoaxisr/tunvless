/* Разбор подписки: vless:// ссылки в список узлов.
 *
 * Подписка — это base64 от списка ссылок, по одной на строку. Ничего сложнее здесь нет,
 * и именно поэтому разбор живёт в steer, а не в клиенте: он не требует ни криптографии,
 * ни сети, проверяется текстом, и его результат нужен и интерфейсу (показать узлы), и
 * сторожу (выбрать живой).
 *
 * Чужие протоколы (hy2, ss, trojan) пропускаются молча, но считаются: подписка обычно
 * общая, и «в ней 26 узлов, а steer видит 17» должно объясняться цифрой, а не догадкой.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vless.h"
/* Ради vless_uuid_form: пригодность идентификатора — такая же часть пригодности узла, как
 * транспорт и security, а правило, по которому он превращается в 16 байт, живёт в одном
 * месте — в vless_proto.c. Библиотек это не тянет. */
#include "vless_proto.h"
/* Ради tr_upgrade_target: путь ws и httpupgrade, на котором Xray споткнулся бы, отбраковывается
 * здесь тем же правилом, по которому транспорт собирает запрос (src/proto/transport/trpath.c —
 * чистые строки, без сети и библиотек). */
#include "trpath.h"
/* Разбор строки encryption (VLESS encryption): годность узла решается здесь, до подключения. Только строки,
 * без криптографии — сюда же входит стенд подписки, у которого библиотеки нет. */
#include "vencp.h"

/* base64: только декодирование и только то, что встречается в подписках — с переводами
 * строк внутри и, возможно, без выравнивающих '='. URL-safe алфавит тоже принимается:
 * часть панелей отдаёт именно его. */
static int b64val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

size_t b64_decode(const char *in, size_t n, char *out, size_t out_n) {
    size_t o = 0;
    /* Накопитель БЕЗ знака и с маской: читаются из него только младшие bits+8 разрядов
     * (bits после уменьшения не больше 7), а старшие копились без нужды — на длинной
     * подписке int переполнялся, то есть разбор недоверенного текста упирался в
     * неопределённое поведение. UBSan на стенде подписки это и показывал:
     * «left shift of 496703836 by 6 places cannot be represented in type int». */
    unsigned acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        /* '=' закрывает блок: недобранные биты — его остаток, а не начало следующего.
         * Без сброса склеенные блоки с выравниванием внутри («QQ==QQ==») сдвигали всё
         * дальнейшее на остаток и давали мусор (I-326). */
        if (in[i] == '=') { acc = 0; bits = 0; continue; }
        int v = b64val((unsigned char)in[i]);
        if (v < 0) continue;                  /* переводы строк, мусор */
        acc = ((acc << 6) | (unsigned)v) & 0x3FFFu;   /* хватает 14 разрядов: 7 + 6 + 1 */
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o + 1 < out_n) out[o++] = (char)((acc >> bits) & 0xFF);
        }
    }
    if (o < out_n) out[o] = '\0';
    return o;
}

/* Процентное декодирование на месте: имена узлов приходят как %F0%9F%8C%8D... и без
 * этого в интерфейсе выглядят мусором. */
/* Адрес, по которому собеседника не бывает в принципе.
 *
 * Только такие: не указан (0.0.0.0, ::), петля (127.0.0.0/8, ::1) и широковещательный.
 * Частные сети сюда НЕ входят — узел в 10.0.0.0/8 это законная настройка внутри своей сети
 * или поверх второго туннеля, и отбрасывать его значило бы решить за человека.
 *
 * Имя не разрешается: подписка приходит из интернета, и разрешение имён на этапе разбора
 * означало бы поход в сеть внутри парсера чужого текста. Строка сравнивается как строка —
 * заглушки панелей пишут адрес цифрами, а не именем.
 */
static int host_leads_nowhere(const char *h) {
    if (!h || !h[0]) return 1;
    if (!strcmp(h, "0.0.0.0") || !strcmp(h, "::") || !strcmp(h, "[::]")) return 1;
    if (!strcmp(h, "::1") || !strcmp(h, "[::1]")) return 1;
    if (!strcmp(h, "255.255.255.255")) return 1;
    /* 127.0.0.0/8 целиком: заглушки встречаются и как 127.0.0.1, и как 127.0.0.53. */
    if (!strncmp(h, "127.", 4)) {
        const char *p = h + 4;
        while (*p) { if ((*p < '0' || *p > '9') && *p != '.') return 0; p++; }
        return 1;
    }
    return 0;
}

/* Имя это или адрес. Нужно security=tls: сертификат выдают на имя, и узел, объявленный
 * одним адресом без sni, проверять не против чего.
 *
 * Разбирается СТРОКОЙ, без inet_pton, и по той же причине, что и выше: этот файл разбирает
 * чужой текст из интернета и не ходит в сеть и не тянет сетевые заголовки. Правило простое и
 * достаточное: двоеточие бывает только у IPv6 (в скобках или без), а строка из одних цифр и
 * точек — это IPv4. Всё остальное — имя. Ошибиться здесь можно лишь в сторону «принять имя
 * за имя», а дальше сертификат всё равно проверяется по-настоящему. */
static int host_is_name(const char *h) {
    if (!h || !h[0]) return 0;
    if (strchr(h, ':') || h[0] == '[') return 0;
    for (const char *p = h; *p; p++)
        if ((*p < '0' || *p > '9') && *p != '.') return 1;
    return 0;
}

static int pct_hex(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    c |= 32;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static void pct_decode(char *s) {
    char *w = s;
    for (char *r = s; *r; r++) {
        if (*r == '%' && r[1] && r[2]) {
            /* Только шестнадцатеричные цифры: прежняя арифметика считала «@» и «`» девяткой
             * (0x40|32 = 0x60 → 9), и «%@@» в имени узла давал байт 0x99 — битый UTF-8. */
            int hi = pct_hex(r[1]), lo = pct_hex(r[2]);
            if (hi >= 0 && lo >= 0) {
                *w++ = (char)((hi << 4) | lo);
                r += 2;
                continue;
            }
        }
        *w++ = *r;
    }
    *w = '\0';
}

static void set_field(char *dst, size_t n, const char *src, size_t len) {
    if (len >= n) len = n - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* Поле ссылки в процентной форме: раскодировать, ПОТОМ обрезать по полю. Наоборот (как было у
 * path) путь в 60 знаков, записанный процентами целиком (`%2Fstatic%2Fv1…` — так его кодируют
 * многие панели), обрезался до раскодирования на трети и уезжал на сервер чужим путём: у xhttp и
 * ws это 404 при исправном узле. */
static void set_pct(char *dst, size_t n, const char *src, size_t len) {
    char tmp[512];
    set_field(tmp, sizeof(tmp), src, len);
    pct_decode(tmp);
    set_field(dst, n, tmp, strlen(tmp));
}

/* Снять с конца строки неполную последовательность UTF-8. Нужно там, где строку обрезал
 * буфер: обрезка идёт по байту, а буква вне ASCII занимает от двух байт, и граница
 * приходится на её середину. Одинокий ведущий байт — не «испорченная буква», а байт,
 * который ни один потребитель истолковать не может: JSON статуса печатает его как есть,
 * и разбирать этот JSON приходится уже интерфейсу. Терять последнюю букву честнее. */
static void utf8_trim_tail(char *s) {
    size_t n = strlen(s);
    if (!n) return;
    unsigned char last = (unsigned char)s[n - 1];
    if (last < 0x80) return;                       /* ASCII — рвать нечего */
    if ((last & 0xC0) != 0x80) { s[n - 1] = '\0'; return; }  /* ведущий байт без продолжения */

    /* Байт продолжения последним: отступить к ведущему и сверить длину. */
    size_t at = n - 1, cont = 1;
    while (at && ((unsigned char)s[at - 1] & 0xC0) == 0x80) { at--; cont++; }
    if (!at) { s[0] = '\0'; return; }              /* одни продолжения — мусор целиком */
    unsigned char lead = (unsigned char)s[at - 1];
    /* Перед продолжениями ASCII: ведущего байта нет, и снимаются только продолжения. Иначе
     * «ab\x80» теряло бы и «b» — букву, которая ни при чём (I-326). */
    if (lead < 0x80) { s[at] = '\0'; return; }
    size_t need = (lead & 0xE0) == 0xC0 ? 1 :
                  (lead & 0xF0) == 0xE0 ? 2 :
                  (lead & 0xF8) == 0xF0 ? 3 : 0;
    if (need && cont == need) return;              /* последовательность целая */
    s[at - 1] = '\0';
}

/* Имя узла: единственное поле, куда подписка кладёт что угодно, включая UTF-8, и потому
 * единственное, где обрезка по байту буфера видна снаружи. Порядок важен: сначала снять
 * оборванную процентную форму (её оставила та же обрезка, декодировать её нечем), потом
 * раскодировать, потом снять оборванную последовательность UTF-8 — она могла появиться и
 * из процентной формы, и из сырых байт во фрагменте ссылки. */
static void set_name(char *dst, size_t n, const char *src) {
    size_t len = strlen(src);
    int cut = len >= n;
    set_field(dst, n, src, len);
    if (cut) {
        size_t l = strlen(dst);
        if (l >= 1 && dst[l - 1] == '%') dst[l - 1] = '\0';
        else if (l >= 2 && dst[l - 2] == '%') dst[l - 2] = '\0';
    }
    pct_decode(dst);
    utf8_trim_tail(dst);
}

/* Длина набивки xhttp из значения `xPaddingBytes`.
 *
 * Значение бывает двух видов, и оба законны у Xray: одно число («512») или диапазон
 * («50-150»). Разбирается вручную, без sscanf: строка приходит из интернета, а sscanf на
 * мусоре ведёт себя тем интереснее, чем мусор изобретательнее.
 *
 * Ничего не понято — поля не трогаются, и дальше работает умолчание. Молчание здесь верно:
 * набивка, которую мы не сумели прочитать, не повод объявлять узел негодным — умолчание
 * Xray подойдёт большинству серверов. */
static void pad_range(struct vless_node *n, const char *v) {
    unsigned a = 0, b = 0;
    const char *p = v;
    while (*p == ' ' || *p == '"') p++;
    if (*p < '0' || *p > '9') return;
    while (*p >= '0' && *p <= '9') { a = a * 10 + (unsigned)(*p - '0'); p++; if (a > 65535) return; }
    if (*p == '-') {
        p++;
        if (*p < '0' || *p > '9') return;
        while (*p >= '0' && *p <= '9') { b = b * 10 + (unsigned)(*p - '0'); p++; if (b > 65535) return; }
    } else {
        b = a;
    }
    if (b < a) return;
    n->pad_from = (uint16_t)a;
    n->pad_to = (uint16_t)b;
}

/* `extra` ссылки — это кусок настроек транспорта в JSON, и нас в нём занимает ровно одно
 * поле. Полного разбора здесь нет намеренно: остальное (xmux, сроки переиспользования
 * соединений) относится к мультиплексору, которого у нас нет, и разбирать его значило бы
 * читать чужие настройки, чтобы их выбросить.
 *
 * Поиск по имени поля, а не разбор объекта: `extra` приезжает уже раскодированным из
 * процентной формы, вложенность в нём одна, и вытащить одно число дешевле, чем заводить
 * второй разбор JSON рядом с тем, что уже есть в этом файле. */
/* Признаки того, что сервер включил обфускацию xhttp, которой у клиента нет: поле присутствует с
 * непустым значением (или true). Ложное срабатывание хуже пропуска не бывает — узел с ними и так не
 * откроется на сервере, ждущем другого запроса. */
static int xh_extra_bad(const char *json) {
    static const char *const keys[] = { "\"downloadSettings\"", "\"sessionIDPlacement\"", "\"seqPlacement\"",
                                        "\"uplinkDataPlacement\"", "\"xPaddingPlacement\"", "\"xPaddingMethod\"" };
    for (size_t i = 0; i < sizeof keys / sizeof *keys; i++) {
        const char *k = strstr(json, keys[i]);
        if (!k) continue;
        k = strchr(k, ':');
        if (!k) continue;
        k++;
        while (*k == ' ') k++;
        if (*k && *k != 'n' && !(k[0] == '"' && k[1] == '"') && *k != '}' && *k != ',') return 1;
    }
    const char *o = strstr(json, "\"xPaddingObfsMode\"");
    if (o && (o = strchr(o, ':'))) { o++; while (*o == ' ') o++; if (!strncmp(o, "true", 4)) return 1; }
    return 0;
}

static void parse_extra(struct vless_node *n, const char *extra) {
    if (xh_extra_bad(extra)) n->xh_extra = 1;
    const char *k = strstr(extra, "\"xPaddingBytes\"");
    if (!k) return;
    k = strchr(k + 15, ':');
    if (!k) return;
    pad_range(n, k + 1);
}


/* ---- длинные значения узла: encryption и pqv ---------------------------------------------------
 *
 * Значения длинные (ключ ML-DSA-65 в base64url — 2603 знака, реле VLESS encryption с ключом ML-KEM-768 —
 * около 1600), а узлов в массиве сотни: по полю в узле это сотни килобайт статической памяти под то,
 * что бывает у единиц. Поэтому узел держит УКАЗАТЕЛЬ на строку из общей таблицы, где одинаковые
 * значения хранятся один раз. Строки не освобождаются: указатель обязан пережить и узел, и его копии
 * (узлы копируются по значению между массивами разбора и стеком туннеля), а повторные разборы той же
 * подписки находят уже занесённое и памяти не прибавляют. Таблица ограничена — переполнение узла не
 * теряет, а объявляет непригодным с названной причиной (без неё хостильная подписка со случайными
 * ключами росла бы в памяти роутера на каждом обновлении). */
#define SUB_INTERN_MAX 256
static const char *g_intern[SUB_INTERN_MAX];
static volatile int g_intern_lock;
/* Метки непригодных значений: разбор не удался, причина уже названа в node_usable. */
static const char SUB_BAD_ENC[] = "!encryption";
static const char SUB_BAD_PQV[] = "!pqv";
static const char SUB_FULL[] = "!full";

static const char *sub_intern(const char *v, size_t n) {
    while (__atomic_test_and_set(&g_intern_lock, __ATOMIC_ACQUIRE)) { }
    const char *r = SUB_FULL;
    for (int i = 0; i < SUB_INTERN_MAX; i++) {
        if (!g_intern[i]) {
            char *c = malloc(n + 1);
            if (c) { memcpy(c, v, n); c[n] = '\0'; g_intern[i] = c; r = c; }
            break;
        }
        if (strlen(g_intern[i]) == n && !memcmp(g_intern[i], v, n)) { r = g_intern[i]; break; }
    }
    __atomic_clear(&g_intern_lock, __ATOMIC_RELEASE);
    return r;
}

/* encryption узла. Пусто и «none» — шифрования нет. Остальное обязано разобраться по правилу Xray
 * (vencp.h): иначе узел помечается меткой и отбраковывается в node_usable. Значение приходит уже
 * раскодированным, с завершающим нулём. */
static void set_encryption(struct vless_node *n, const char *v) {
    n->encryption = NULL;
    if (!v[0] || !strcmp(v, "none")) return;
    struct venc_cfg c;
    if (vencp_parse(v, &c, NULL) != 0) { n->encryption = SUB_BAD_ENC; return; }
    n->encryption = sub_intern(v, strlen(v));
}

/* pqv / mldsa65Verify: открытый ключ ML-DSA-65, base64url, ровно 1952 байта. */
static void set_pqv(struct vless_node *n, const char *v) {
    n->pqv = NULL;
    if (!v[0]) return;
    if (vencp_b64url_len(v, strlen(v)) != 1952) { n->pqv = SUB_BAD_PQV; return; }
    n->pqv = sub_intern(v, strlen(v));
}

/* ---- проверка сертификата узла: pcs, pks, vcn, allowInsecure ------------------------------------
 *
 * Xray-core (transport/internet/tls/config.go, infra/conf/transport_security.go) знает два способа
 * не полагаться на хранилище корней: pinnedPeerCertSha256 (`pcs` в ссылке) — SHA-256 сертификата в
 * hex, через запятую, двоеточия OpenSSL допустимы; verifyPeerCertByName (`vcn`) — имена, против
 * которых проверяется цепочка ВМЕСТО SNI. allowInsecure Xray снял совсем (конфиг с ним не
 * собирается), а в ссылках и чужих подписках он живёт по-прежнему. sing-box держит отпечаток иначе —
 * SHA-256 от SubjectPublicKeyInfo в base64 (`certificate_public_key_sha256`); он хранится отдельно
 * (pks), потому что считается от другого куска сертификата и смешивать два вида отпечатков нельзя.
 *
 * Отпечаток приводится к одному виду (64 знака hex строчными) ЗДЕСЬ, при разборе: испорченный
 * отпечаток — непригодный узел с названной причиной, а не проверка, которая на каждом соединении
 * молча ничего не сравнивает. */
static const char SUB_BAD_PIN[] = "!pin";

static const char *pin_slot(const struct vless_node *n, int spki) { return spki ? n->pks : n->pcs; }

static void add_pins(struct vless_node *n, const char *v, int spki) {
    const char *cur = pin_slot(n, spki);
    if (cur == SUB_BAD_PIN || cur == SUB_FULL) return;
    char buf[1100];
    size_t bl = 0;
    if (cur) bl = (size_t)snprintf(buf, sizeof buf, "%s", cur);
    const char *p = v;
    int bad = 0;
    while (*p && !bad) {
        const char *e = strchr(p, ',');
        size_t tn = e ? (size_t)(e - p) : strlen(p);
        while (tn && (*p == ' ' || *p == '\t')) { p++; tn--; }
        while (tn && (p[tn - 1] == ' ' || p[tn - 1] == '\t')) tn--;
        unsigned char raw[32] = { 0 };
        if (tn) {
            if (spki) {
                char d[48];
                bad = tn < 43 || tn > 44 || b64_decode(p, tn, d, sizeof d) != 32;
                if (!bad) memcpy(raw, d, 32);
            } else {
                /* Двоеточия — привычная запись OpenSSL (`AB:CD:…`), Xray их отбрасывает. */
                size_t k = 0;
                for (size_t i = 0; i < tn && !bad; i++) {
                    int c = (unsigned char)p[i], h;
                    if (c == ':') continue;
                    h = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10
                        : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
                    if (h < 0 || k >= 64) { bad = 1; break; }
                    if (k & 1) raw[k / 2] = (unsigned char)(raw[k / 2] << 4 | h);
                    else raw[k / 2] = (unsigned char)h;
                    k++;
                }
                if (!bad && k != 64) bad = 1;
            }
            if (!bad) {
                if (bl + 66 >= sizeof buf) bad = 1;
                else {
                    if (bl) buf[bl++] = ',';
                    for (int i = 0; i < 32; i++) bl += (size_t)snprintf(buf + bl, 3, "%02x", raw[i]);
                }
            }
        }
        if (!e) break;
        p = e + 1;
    }
    const char *r = bad ? SUB_BAD_PIN : bl ? sub_intern(buf, bl) : NULL;
    if (spki) n->pks = r; else n->pcs = r;
}

/* verifyPeerCertByName: имена через запятую, пробелы вокруг отбрасываются, пустые пропускаются
 * (так читает и Xray). */
static void set_vcn(struct vless_node *n, const char *v) {
    char buf[300];
    size_t bl = 0;
    n->vcn = NULL;
    const char *p = v;
    while (*p) {
        const char *e = strchr(p, ',');
        size_t tn = e ? (size_t)(e - p) : strlen(p);
        while (tn && (*p == ' ' || *p == '\t')) { p++; tn--; }
        while (tn && (p[tn - 1] == ' ' || p[tn - 1] == '\t')) tn--;
        if (tn) {
            if (bl + tn + 2 >= sizeof buf) { n->vcn = SUB_BAD_PIN; return; }
            if (bl) buf[bl++] = ',';
            memcpy(buf + bl, p, tn);
            bl += tn;
        }
        if (!e) break;
        p = e + 1;
    }
    if (bl) n->vcn = sub_intern(buf, bl);
}

/* allowInsecure / insecure / skip-cert-verify: 1, true, yes — «включено». Всё остальное, в том числе
 * пустое, — выключено: включать отказ проверки сертификата догадкой нельзя, выключать можно. */
static int truthy_flag(const char *v) {
    return !strcmp(v, "1") || !strcasecmp(v, "true") || !strcasecmp(v, "yes");
}

/* Ключ `insecure` выхода (см. vless.h). */
static volatile int g_insecure;
void vless_set_insecure(int on) { g_insecure = on ? 1 : 0; }
int vless_insecure(void) { return g_insecure; }

/* Значение параметра ссылки в куче-буфере: длинные значения (pqv, encryption) не помещаются в
 * узел, а стек рабочих потоков мал. Процентная форма раскрывается. Возвращает NULL при нехватке памяти. */
static char *param_dup(const char *v, size_t vlen) {
    char *c = malloc(vlen + 1);
    if (!c) return NULL;
    memcpy(c, v, vlen);
    c[vlen] = '\0';
    pct_decode(c);
    return c;
}

/* Пригодность разобранного узла — общее правило для обоих путей разбора; тело ниже. */
static int node_usable(struct vless_node *n);

/* vless://UUID@host:port?params#name
 *
 * Возвращает 0, если ссылка разобрана и узел ПРИГОДЕН. Непригодный узел — это не ошибка
 * подписки: сервер может предлагать транспорт, которого клиент не умеет, и правильное
 * поведение — пропустить его, а не отказаться от всей подписки. */
/* Порт из строки цифр: 1..65535, иначе 0. Одно место на ссылку и на конфиг Xray. */
static uint16_t port_of(const char *s) {
    if (!*s) return 0;
    unsigned long v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return 0;
        v = v * 10 + (unsigned long)(*s - '0');
        if (v > 65535) return 0;
    }
    return (uint16_t)v;
}

int vless_parse_url(const char *url, struct vless_node *n) {
    memset(n, 0, sizeof(*n));
    if (strncmp(url, "vless://", 8) != 0) return -1;
    const char *p = url + 8;

    const char *at = strchr(p, '@');
    if (!at) return -1;
    set_field(n->uuid, sizeof(n->uuid), p, (size_t)(at - p));

    p = at + 1;
    /* Границы: хост и порт лежат ДО '?' и '#', параметры — до '#'. Иначе имя узла «Fast?type=ws»
     * без параметров читалось как параметры, а «host?type=tcp#name:1» — как хост с портом 1. */
    const char *hash = strchr(p, '#');
    const char *hp_end = hash ? hash : p + strlen(p);
    const char *qmark = memchr(p, '?', (size_t)(hp_end - p));
    const char *colon = memchr(p, ':', (size_t)((qmark ? qmark : hp_end) - p));
    if (!colon) return -1;
    set_field(n->host, sizeof(n->host), p, (size_t)(colon - p));
    {
        /* Порт — только цифры до конца хоста и в диапазоне 1..65535: atoi давал 4464 на
         * «:70000», 65535 на «:-1» и 443 на «:443abc», и узел шёл не туда. */
        char pnum[8];
        const char *pe = colon + 1;
        size_t pl = 0;
        while (pe < (qmark ? qmark : hp_end) && *pe >= '0' && *pe <= '9' && pl + 1 < sizeof(pnum))
            pnum[pl++] = *pe++;
        pnum[pl] = '\0';
        if (!pl || pe != (qmark ? qmark : hp_end)) return -1;
        n->port = port_of(pnum);
    }
    if (!n->port) return -1;

    /* Имя узла: за '#', и оно единственное, что может содержать что угодно. */
    if (hash) {
        set_name(n->name, sizeof(n->name), hash + 1);
    }

    /* Параметры. Значения по умолчанию — те, что подразумевает VLESS, когда поле
     * опущено: type=tcp и security=none встречаются именно так. */
    snprintf(n->type, sizeof(n->type), "tcp");
    if (qmark) {
        const char *end = hash && hash > qmark ? hash : qmark + strlen(qmark);
        const char *k = qmark + 1;
        while (k < end) {
            const char *amp = memchr(k, '&', (size_t)(end - k));
            const char *stop = amp ? amp : end;
            const char *eq = memchr(k, '=', (size_t)(stop - k));
            if (eq) {
                size_t klen = (size_t)(eq - k), vlen = (size_t)(stop - eq - 1);
                const char *v = eq + 1;
                if (!strncmp(k, "type", klen) && klen == 4) set_field(n->type, sizeof(n->type), v, vlen);
                else if (klen == 8 && !strncmp(k, "security", 8)) set_field(n->security, sizeof(n->security), v, vlen);
                else if (klen == 3 && !strncmp(k, "sni", 3)) set_field(n->sni, sizeof(n->sni), v, vlen);
                else if (klen == 2 && !strncmp(k, "fp", 2)) set_field(n->fp, sizeof(n->fp), v, vlen);
                else if (klen == 3 && !strncmp(k, "pbk", 3)) set_field(n->pbk, sizeof(n->pbk), v, vlen);
                else if (klen == 3 && !strncmp(k, "sid", 3)) set_field(n->sid, sizeof(n->sid), v, vlen);
                else if (klen == 4 && !strncmp(k, "flow", 4)) set_field(n->flow, sizeof(n->flow), v, vlen);
                /* encryption и pqv — постквантовая часть Xray-core (паритет 26.9): шифрование VLESS и
                 * проверка подписи ML-DSA-65 сертификата Reality. Значения длинные — см. sub_intern. */
                else if (klen == 10 && !strncmp(k, "headerType", 10)) { if (vlen == 4 && !strncmp(v, "http", 4)) n->tcp_http = 1; }
                else if (klen == 10 && !strncmp(k, "encryption", 10)) {
                    char *d = param_dup(v, vlen);
                    if (d) { set_encryption(n, d); free(d); } else n->encryption = SUB_BAD_ENC;
                }
                else if (klen == 3 && !strncmp(k, "pqv", 3)) {
                    char *d = param_dup(v, vlen);
                    if (d) { set_pqv(n, d); free(d); } else n->pqv = SUB_BAD_PQV;
                }
                /* pcs / vcn — pinnedPeerCertSha256 и verifyPeerCertByName Xray-core; allowInsecure (и
                 * insecure, как пишут панели) подписка нести вправе, но выключить проверку сама не
                 * может — см. node_usable. */
                else if ((klen == 3 && !strncmp(k, "pcs", 3)) || (klen == 3 && !strncmp(k, "vcn", 3))) {
                    char *d = param_dup(v, vlen);
                    if (d) {
                        if (k[0] == 'p') add_pins(n, d, 0); else set_vcn(n, d);
                        free(d);
                    } else if (k[0] == 'p') n->pcs = SUB_BAD_PIN; else n->vcn = SUB_BAD_PIN;
                }
                else if ((klen == 13 && !strncmp(k, "allowInsecure", 13)) || (klen == 8 && !strncmp(k, "insecure", 8))) {
                    char *d = param_dup(v, vlen);
                    if (d) { if (truthy_flag(d)) n->allow_insecure = 1; free(d); }
                }
                else if (klen == 4 && !strncmp(k, "path", 4)) set_pct(n->path, sizeof(n->path), v, vlen);
                else if (klen == 11 && !strncmp(k, "serviceName", 11)) { set_field(n->service, sizeof(n->service), v, vlen); pct_decode(n->service); }
                else if (klen == 4 && !strncmp(k, "mode", 4)) set_field(n->mode, sizeof(n->mode), v, vlen);
                /* host — заголовок Host у ws и httpupgrade. У xhttp в ссылке он тоже бывает, но
                 * xhttp его не читает: :authority там — sni, как было. */
                else if (klen == 4 && !strncmp(k, "host", 4)) set_pct(n->http_host, sizeof(n->http_host), v, vlen);
                /* extra — настройки транспорта в JSON. Читается ради длины набивки: сервер
                 * её ПРОВЕРЯЕТ и на чужую отвечает 400 (см. pad_range). */
                else if (klen == 5 && !strncmp(k, "extra", 5)) {
                    /* Буфер под ПРОЦЕНТНУЮ форму: она втрое длиннее текста, и 256 байт
                     * обрезали JSON до раскодирования — xPaddingBytes дальше ~85 знаков
                     * пропадал молча, набивка оставалась 100…1000, и сервер отвечал 400 —
                     * ровно тот симптом, ради которого поле и заведено. */
                    char ex[2048];
                    set_field(ex, sizeof(ex), v, vlen);
                    pct_decode(ex);
                    parse_extra(n, ex);
                }
            }
            if (!amp) break;
            k = amp + 1;
        }
    }

    /* Пригодность. Проверяется здесь, а не при подключении, чтобы непригодный узел не
     * попал в список кандидатов и сторож не тратил на него попытки.
     *
     * security=none — это VLESS БЕЗ TLS, голый протокол по TCP. Он поддержан: шифровать
     * там нечего, а сам VLESS реализован целиком. Такой узел осмыслен внутри доверенной
     * сети или за уже защищённым каналом, и отбрасывать его вместе с неподдержанными
     * транспортами было бы ошибкой — причины у них разные. Пустое поле security означает
     * то же самое: в ссылке его просто опускают. */
    return node_usable(n);
}

/* Узел ws или httpupgrade: то, на чём Xray споткнулся бы сам, — заранее и с причиной. 1 —
 * непригоден (причина в skip_reason).
 *
 *   - Vision (flow xtls-rprx-vision) поверх них не бывает: Xray требует для Vision голую связь
 *     TLS или REALITY и отказывает («failed to use xtls-rprx-vision, maybe "security" is not
 *     "tls"…»), а у нас прямое копирование Vision прочитало бы сокет мимо кадров;
 *   - путь, который Xray не разобрал бы однозначно или у ws не открыл бы вовсе (trpath.h) — одно
 *     правило с транспортом, чтобы «пригоден» здесь значило «откроется» там;
 *   - host — имя для заголовка Host: без пробелов и управляющих знаков, иначе строка запроса
 *     рвётся посередине;
 *   - заголовки из конфига, которые не влезли или негодны (headers_bad, см. xray_headers). */
static int upg_node_bad(struct vless_node *n, int ws) {
    if (n->flow[0]) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "vision поверх %s не бывает", n->type);
        return 1;
    }
    char tgt[1024];
    const char *why = "";
    if (tr_upgrade_target(n->path, ws, tgt, sizeof(tgt), &why) != 0) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "%s", why);
        return 1;
    }
    for (const char *p = n->http_host; *p; p++) {
        if ((unsigned char)*p <= 0x20 || *p == 0x7f) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "негодный host у %s", n->type);
            return 1;
        }
    }
    if (n->headers_bad) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "негодные headers у %s", n->type);
        return 1;
    }
    return 0;
}

/* Пригоден ли РАЗОБРАННЫЙ узел. 0 — да, 1 — нет, причина в n->skip_reason.
 *
 * Отдельной функцией, потому что путей разбора теперь два: ссылка vless:// и конфиг Xray в
 * подписке (см. parse_xray ниже). Правило пригодности у них обязано быть одно — иначе узел,
 * непригодный в одном виде, окажется пригодным в другом, и человек получит «узлов два,
 * туннель не работает, сказать нечего» ровно там, где мы этого и добивались избежать.
 *
 * Поля, которых во ссылке не было, к этому моменту уже заполнены умолчаниями: делает это
 * первая же строка. */
static int node_usable(struct vless_node *n) {
    if (!n->security[0]) snprintf(n->security, sizeof(n->security), "none");

    /* flow=xtls-rprx-vision-udp443 — тот же Vision, но с разрешением UDP/443 в потоке (Xray-core). У нас
     * UDP идёт отдельной командой и без flow, поэтому разрешение ничего не меняет, а имя приводится к
     * обычному: в запросе VLESS Xray тоже отправляет flow без суффикса. */
    if (!strcmp(n->flow, "xtls-rprx-vision-udp443")) snprintf(n->flow, sizeof(n->flow), "xtls-rprx-vision");

    /* Постквантовые поля. Метки ставит разбор (set_encryption, set_pqv): значение не по правилу Xray или
     * таблица длинных значений полна. Причины короткие — skip_reason всего 64 байта. */
    if (n->encryption == SUB_BAD_ENC) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "encryption не поддержан");
        return 1;
    }
    if (n->pqv == SUB_BAD_PQV) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "pqv: не ключ ML-DSA-65");
        return 1;
    }
    if (n->tcp_http && !strcmp(n->type, "tcp")) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "tcp headerType=http не поддержан");
        return 1;
    }
    if (n->xh_extra && !strcmp(n->type, "xhttp")) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "xhttp: обфускация не поддержана");
        return 1;
    }
    if (n->encryption == SUB_FULL || n->pqv == SUB_FULL || n->pcs == SUB_FULL || n->pks == SUB_FULL ||
        n->vcn == SUB_FULL) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "слишком много разных ключей");
        return 1;
    }
    /* Проверка сертификата касается только security=tls: у reality подлинность доказывает сам
     * протокол, а pcs/vcn/allowInsecure, попавшие в такую ссылку, ничего не значат. Испорченный
     * отпечаток у tls — непригодный узел, а не проверка, которая молча ничего не сверяет. */
    if (!strcmp(n->security, "tls")) {
        if (n->pcs == SUB_BAD_PIN) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "pcs: не SHA-256 в hex");
            return 1;
        }
        if (n->pks == SUB_BAD_PIN) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "certificate_public_key_sha256: не SHA-256");
            return 1;
        }
        if (n->vcn == SUB_BAD_PIN) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "vcn: слишком длинный список имён");
            return 1;
        }
        /* Решение безопасности: подписка не выключает проверку сертификата сама. Узел с allowInsecure
         * пригоден, только если человек явно поставил `insecure` у выхода. */
        if (n->allow_insecure && !g_insecure) {
            snprintf(n->skip_reason, sizeof(n->skip_reason), "allowInsecure: включите insecure у выхода явно");
            return 1;
        }
        n->insecure = g_insecure ? 1 : 0;
    }

    /* Идентификатор пользователя. Проверяется ЗДЕСЬ по той же причине, что и всё
     * остальное в этом блоке: непригодный узел не должен попасть в кандидаты.
     *
     * Пригодность здесь — это правило Xray (см. vless_uuid_form): либо шестнадцатеричный
     * UUID в 32-36 знаков, либо короткая строка до 30 знаков, из которой UUID выводится
     * хэшем. Панели выдают и то, и другое, и «TMG_74317ba5f91» — законный узел, а не
     * ошибка. Непригодны ровно три случая, и стать 16 байтами они не могут никак:
     * пустая строка, ровно 31 знак (для вывода длинно, для UUID коротко) и длиннее
     * UUID; отдельно — строка нужной длины с посторонним знаком внутри.
     *
     * До этой проверки такой узел считался пригодным, доходил до подключения и молчал:
     * проба отвечала «UUID неразборчив», а туннель ронял соединение без причины. */
    switch (vless_uuid_form(n->uuid)) {
    case VLESS_UUID_EMPTY:
        snprintf(n->skip_reason, sizeof(n->skip_reason), "идентификатор пуст");
        return 1;
    case VLESS_UUID_GAP:
        snprintf(n->skip_reason, sizeof(n->skip_reason),
                 "идентификатор: 31 знак, нужен UUID");
        return 1;
    case VLESS_UUID_TOOLONG:
        snprintf(n->skip_reason, sizeof(n->skip_reason), "идентификатор длиннее UUID");
        return 1;
    case VLESS_UUID_NOTHEX:
        snprintf(n->skip_reason, sizeof(n->skip_reason), "UUID с недопустимым знаком");
        return 1;
    default:
        break;
    }

    if (strcmp(n->security, "reality") != 0 && strcmp(n->security, "none") != 0 &&
        strcmp(n->security, "tls") != 0) {
        /* Остаётся непригодным xtls: это уже не «TLS с проверкой цепочки», а свой обмен,
         * которого у нас нет. tls поддержан — см. certverify.c и ветку в client.c. */
        snprintf(n->skip_reason, sizeof(n->skip_reason), "security=%s не поддержан",
                 n->security);
        return 1;
    }

    /* У обычного TLS имя обязательно, и отбраковывается оно ЗДЕСЬ, а не при подключении.
     *
     * Проверять сертификат не против чего: sni — это то, что мы просим у сервера, и он же
     * то, что должно найтись в сертификате. Узел без sni проверяется против адреса, и если
     * адрес — это IP, сертификат на него почти наверняка не выдан. Сказать об этом заранее
     * честнее, чем потратить попытку сторожа и вернуть «сервер не доказал подлинность»:
     * причина-то не в сервере. (У reality пустой sni, наоборот, законен — см. ниже.) */
    if (strcmp(n->security, "tls") == 0 && !n->sni[0] && !host_is_name(n->host)) {
        snprintf(n->skip_reason, sizeof(n->skip_reason),
                 "tls по адресу без sni: нечем сверить");
        return 1;
    }
    /* Ключ сервера обязателен: без него Reality нечем проверить, и узел не поднимется.
     *
     * А ВОТ ИМЯ (sni) — НЕТ, и раньше его отсутствие тоже отбраковывало узел. Reality
     * сверяет присланное имя со своим списком `serverNames`, и пустая строка в этом списке
     * законна: тогда сервер ждёт ClientHello БЕЗ расширения server_name, а клиенты Xray его
     * и не шлют. Снято на живой подписке владельца: панель во всех форматах разом — ссылка
     * vless://, вариант для Happ, YAML для Clash — отдаёт узел без `sni`, то есть это выбор
     * владельца сервера, а не потеря по дороге. Мы такой узел объявляли непригодным, и
     * подписка из одного узла выглядела пустой. ClientHello без имени собирает reality.c. */
    if (!strcmp(n->security, "reality") && !n->pbk[0]) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "reality без pbk");
        return 1;
    }
    const int upg_ws = !strcmp(n->type, "ws"), upg = upg_ws || !strcmp(n->type, "httpupgrade");
    if (strcmp(n->type, "tcp") != 0 && strcmp(n->type, "grpc") != 0 &&
        strcmp(n->type, "xhttp") != 0 && !upg) {
        snprintf(n->skip_reason, sizeof(n->skip_reason), "транспорт %s не поддержан", n->type);
        return 1;
    }
    if (upg && upg_node_bad(n, upg_ws)) return 1;

    /* Узел, который никуда не ведёт. Отдельная причина, а не «не подключился»: панели,
     * привязывающие подписку к устройствам, отвечают клиенту без идентификатора не отказом,
     * а ЗАГЛУШКОЙ — законными ссылками vless:// на `0.0.0.0:1`, где сообщение человеку
     * спрятано в ИМЯ узла («📱 Неправильный клиент», «🔌 Лимит устройств достигнут»).
     *
     * Разбор такую ссылку принимает целиком, и правильно: по форме она безупречна. Но
     * пригодной она быть не может — по этому адресу не существует собеседника, и connect
     * либо уйдёт в свой же роутер (0.0.0.0 ядро трактует как локальный), либо в чужую сеть.
     * Раньше такой узел попадал в кандидаты, тратил попытки сторожа и давал ровно тот вид
     * отказа, которого в этом коде нет больше нигде: «узлов два, туннель не работает,
     * сказать нечего».
     *
     * Названная причина при этом ДОНОСИТ сообщение панели: skip_reason уезжает в интерфейс
     * вместе с примером, а примером служит имя узла — то есть человек читает «узел ведёт в
     * 0.0.0.0 — например „Неправильный клиент“» и понимает, что дело в панели, а не в
     * роутере.
     *
     * Проверяются только адреса, у которых собеседника не бывает В ПРИНЦИПЕ: не указан
     * (0.0.0.0, ::), локальная петля (127.0.0.0/8, ::1) и широковещательный. Частные сети
     * НЕ проверяются: узел в 10.0.0.0/8 — законная и рабочая настройка внутри своей сети или
     * поверх второго туннеля. */
    if (host_leads_nowhere(n->host)) {
        /* Длина держится в пределах skip_reason (64 байта, а буква кириллицы это два):
         * обрезка причины по границе буфера разрубила бы букву посередине, и в JSON уехала
         * бы недобитая последовательность — ровно то, чем ломался вывод стенда в I-029. */
        snprintf(n->skip_reason, sizeof(n->skip_reason), "%.20s: отвечать некому", n->host);
        return 1;
    }

    /* Режим xhttp, которого мы не умеем, называется ЗДЕСЬ, а не выясняется при
     * подключении: непригодный узел не должен попадать в кандидаты и тратить попытки.
     *
     * Поддержаны все три ходовых:
     *
     *   stream-one — один запрос POST, тело запроса наверх, тело ответа вниз. Дешевле
     *     всех, и его же выбирает сам Xray при reality с mode=auto, поэтому «auto» ведёт
     *     сюда же;
     *   stream-up  — GET за загрузкой и длинный POST под выгрузку;
     *   packet-up  — GET за загрузкой и череда коротких POST по куску в каждом.
     *
     * Остаётся неподдержанным «stream-down» и всё незнакомое: у первого нет выгрузки
     * вовсе, он половина связки с отдельным download-сервером, которой у нас нет. */
    if (!strcmp(n->type, "xhttp") && n->mode[0] &&
        strcmp(n->mode, "auto") != 0 && strcmp(n->mode, "stream-one") != 0 &&
        strcmp(n->mode, "stream-up") != 0 && strcmp(n->mode, "packet-up") != 0) {
        snprintf(n->skip_reason, sizeof(n->skip_reason),
                 "xhttp mode=%s не поддержан", n->mode);
        return 1;
    }
    return 0;
}

/* Отнести непригодный узел к его причине. Единственное место, где растёт skipped:
 * счётчик и объяснение обязаны сходиться, а два независимых инкремента — это ровно тот
 * случай, когда «пропущено 26» и «причин на 24 узла» уезжают друг от друга молча. */
static void skip_note(struct vless_sub_stats *st, const struct vless_node *n,
                      const char *reason) {
    if (!st) return;
    st->skipped++;
    for (size_t i = 0; i < st->reasons_n; i++) {
        if (!strcmp(st->reasons[i].reason, reason)) { st->reasons[i].count++; return; }
    }
    if (st->reasons_n >= VLESS_SKIP_REASONS) { st->reasons_dropped++; return; }
    struct vless_skip *s = &st->reasons[st->reasons_n++];
    snprintf(s->reason, sizeof(s->reason), "%s", reason);
    /* Пример — чтобы причину можно было привязать к узлу в подписке. Имя есть не
     * всегда: во ссылке без '#' его нет вовсе, а у неразобранной ссылки может не быть
     * и host — тогда пример остаётся пустым, и это честнее выдуманного «узел 3». */
    if (n && n->name[0]) snprintf(s->example, sizeof(s->example), "%s", n->name);
    else if (n && n->host[0]) snprintf(s->example, sizeof(s->example), "%s:%u",
                                      n->host, n->port);
    s->count = 1;
}

/* ---- подписка в виде конфига Xray -------------------------------------------
 *
 * ЗАЧЕМ ЭТО ВООБЩЕ ЕСТЬ. Панели с привязкой к устройствам выбирают формат ответа по
 * User-Agent, и списка ссылок vless:// среди вариантов может не быть НИ ОДНОГО. Замерено на
 * живой подписке: незнакомому клиенту (steer, curl, sing-box, Nekoray) отдаётся заглушка из
 * ссылок ss:// на localhost:1234 с именами «Неправильный клиент» и «Подключись через Happ»;
 * Happ, v2rayNG и Streisand получают конфиг Xray в JSON; Clash — свой YAML; SFI — конфиг
 * sing-box. То есть подписка, у которой узлы совершенно исправны (проверено пробой: восемь
 * из девяти отвечают), для движка выглядела как «ни одного пригодного узла».
 *
 * Притворяться чужим клиентом — не выход, и не из принципа: JSON приезжает и Happ-у, значит
 * читать его пришлось бы всё равно. Поэтому читаем.
 *
 * ЧТО ИМЕННО ЧИТАЕТСЯ. Массив конфигов `[{...},{...}]` или один конфиг `{...}`; в каждом
 * берутся `outbounds`, а из них — те, у которых `protocol` равен `vless`. Всё остальное
 * (dns, routing, inbounds, freedom, blackhole) пропускается: это настройки клиента, к
 * которому подписка обращается, а не описание узла.
 *
 * Разборщик свой и намеренно маленький — как и ридер спеки (src/lib/jsonr.c), он не общий
 * парсер JSON, а обход ровно той формы, которую ждём. Ридер спеки теперь общий (jsonr.h), но
 * брать его сюда всё равно незачем, по двум причинам. Он строг там, где подписке нужна
 * терпимость: строку длиннее буфера он отвергает через struct err (для имени выхода или пути
 * так и надо — обрезанное имя устройства ядро не возьмёт), а имя узла из панели здесь молча
 * обрезается — это подпись, и из-за длинной подписи терять узел нельзя. И стенд подписки
 * (tests/submatch.c) включает этот файл исходником и собирается в одиночку, без lib/, модели и
 * криптобиблиотеки, — это его главное свойство: чужой текст из интернета проверяется без сети и без
 * docker.
 */
struct sj { const char *p; };

static void sj_ws(struct sj *j) {
    while (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r') j->p++;
}

/* Строка в buf. Экранирование понимается ровно настолько, чтобы \" не оборвала строку: имена
 * узлов приходят из панели и содержат что угодно, а \uXXXX в них не встречается — панели
 * пишут UTF-8 как есть. Непонятая последовательность попадает в buf буквально, и это лучше,
 * чем отказ: имя — единственное поле, которому позволено быть любым. */
static int sj_str(struct sj *j, char *buf, size_t n) {
    sj_ws(j);
    if (*j->p != '"') return -1;
    j->p++;
    size_t i = 0;
    while (*j->p && *j->p != '"') {
        if (*j->p == '\\' && j->p[1]) j->p++;
        if (i + 1 < n) buf[i++] = *j->p;
        j->p++;
    }
    if (*j->p != '"') return -1;
    j->p++;
    if (n) buf[i] = '\0';
    return 0;
}

/* Пропустить одно значение любого типа. Нужен за тем же, за чем js_skip ридеру спеки
 * (src/lib/jsonr.c): чтобы незнакомый ключ
 * не толковался молча, а именно пропускался. */
static void sj_skip(struct sj *j) {
    sj_ws(j);
    if (*j->p == '"') { char t[8]; sj_str(j, t, sizeof(t)); return; }
    if (*j->p == '{' || *j->p == '[') {
        char open = *j->p, close = open == '{' ? '}' : ']';
        int depth = 0;
        do {
            if (*j->p == '"') { char t[8]; sj_str(j, t, sizeof(t)); continue; }
            if (*j->p == open) depth++;
            else if (*j->p == close) depth--;
            j->p++;
        } while (*j->p && depth > 0);
        return;
    }
    while (*j->p && *j->p != ',' && *j->p != '}' && *j->p != ']') j->p++;
}

/* Войти в объект и отдавать его ключи по одному. 0 — ключ в key, 1 — объект кончился,
 * -1 — это не объект. Значение читает вызывающий; не прочитал — обязан позвать sj_skip. */
static int sj_obj_key(struct sj *j, int *first, char *key, size_t key_n) {
    sj_ws(j);
    if (*first) {
        if (*j->p != '{') return -1;
        j->p++;
        *first = 0;
    } else {
        sj_ws(j);
        if (*j->p == ',') j->p++;
    }
    sj_ws(j);
    if (*j->p == '}') { j->p++; return 1; }
    if (sj_str(j, key, key_n) != 0) return -1;
    sj_ws(j);
    if (*j->p != ':') return -1;
    j->p++;
    return 0;
}

/* Тот же приём для массива: 0 — элемент начинается здесь, 1 — массив кончился. */
static int sj_arr_next(struct sj *j, int *first) {
    sj_ws(j);
    if (*first) {
        if (*j->p != '[') return -1;
        j->p++;
        *first = 0;
    } else {
        sj_ws(j);
        if (*j->p == ',') j->p++;
        /* После элемента бывает только запятая или конец массива. Всё прочее — брак, и на
         * нём разбор обязан ОСТАНОВИТЬСЯ: прежде он отвечал «есть следующий элемент», не
         * сдвигая указатель, а читатель элемента на не-объекте тоже не сдвигался — и цикл
         * крутился вечно на `[null]`, `[}`, порте строкой и ещё четырёх формах кривого JSON,
         * который приходит из интернета (подписка с панели). Висел и процесс туннеля, и
         * интерфейс. */
        else if (*j->p != ']') return -1;
    }
    sj_ws(j);
    if (*j->p == ']') { j->p++; return 1; }
    return 0;
}

/* Настройки ws или httpupgrade из конфига — до того, как станет известно, какой из двух у узла.
 * Конфиг вправе нести оба объекта (и ещё xhttpSettings) сразу, а решает network — который может
 * стоять и после них, поэтому разобранное складывается сюда и переносится в узел в конце
 * (xray_stream). Иначе путь из wsSettings затирал бы путь xhttp у узла xhttp. */
struct upg_cfg {
    char path[sizeof(((struct vless_node *)0)->path)];
    char host[sizeof(((struct vless_node *)0)->http_host)];
    char headers[sizeof(((struct vless_node *)0)->headers)];
    uint8_t bad;
};

static int ci_eq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y) return 0;
    }
    return *a == *b;
}

/* headers конфига Xray (map[string]string) — в строки «Имя: значение\n».
 *
 * Отбраковка (bad), а не молчаливый пропуск, потому что заголовок узла — часть облика, который
 * продавец выбрал для своего сервера или CDN перед ним: узел, ушедший без него, может
 * отвечать 403 и выглядеть мёртвым. Негодно:
 *   - значение не строкой — Xray такой конфиг не загрузит вовсе;
 *   - имя не из знаков токена HTTP или длиннее 40, значение с управляющим знаком (перевод строки
 *     сделал бы из одного заголовка два) или длиннее 250 — запрос у нас собирается из строк;
 *   - у ws — Upgrade, Connection и Sec-WebSocket-Key/Version/Extensions: gorilla на них отказывает
 *     («duplicate header not allowed»), то есть и у Xray узел не открылся бы. У httpupgrade Xray их
 *     принимает (ключ как написан, Connection и Upgrade транспорт ставит поверх своими
 *     каноническими ключами) — и здесь принимаются, запрос повторяет Xray (trupgrade.c);
 *   - Host у httpupgrade — Xray отвергает конфиг («"headers" can't contain "host"»). У ws Host
 *     из headers Xray переносит в host (если тот пуст) и из заголовков убирает — так и здесь.
 *   - не влезло в буфер узла. */
static void xray_headers(struct sj *j, struct upg_cfg *u, int hu) {
    int f = 1;
    char key[64], val[256];
    size_t o = strlen(u->headers);
    while (sj_obj_key(j, &f, key, sizeof(key)) == 0) {
        sj_ws(j);
        if (*j->p != '"') { sj_skip(j); u->bad = 1; continue; }
        val[0] = '\0';
        sj_str(j, val, sizeof(val));
        size_t kn = strlen(key), vn = strlen(val);
        if (ci_eq(key, "host")) {
            if (hu) u->bad = 1;
            else if (!u->host[0]) set_field(u->host, sizeof(u->host), val, vn);
            continue;
        }
        int ok = kn > 0 && kn <= 40 && vn <= 250;
        for (size_t i = 0; ok && i < kn; i++) {
            unsigned char c = (unsigned char)key[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  (c && strchr("!#$%&'*+-.^_`|~", c))))
                ok = 0;
        }
        for (size_t i = 0; ok && i < vn; i++) {
            unsigned char c = (unsigned char)val[i];
            if ((c < 0x20 && c != '\t') || c == 0x7f) ok = 0;
        }
        if (!hu && (ci_eq(key, "upgrade") || ci_eq(key, "connection") ||
                    ci_eq(key, "sec-websocket-key") || ci_eq(key, "sec-websocket-version") ||
                    ci_eq(key, "sec-websocket-extensions")))
            ok = 0;
        if (!ok || o + kn + 2 + vn + 1 >= sizeof(u->headers)) { u->bad = 1; continue; }
        o += (size_t)snprintf(u->headers + o, sizeof(u->headers) - o, "%s: %s\n", key, val);
    }
}

/* wsSettings и httpupgradeSettings: path, host, headers. Пустой host не затирает Host из
 * headers (у Xray пустой host — «не задан»). */
static void xray_upg(struct sj *j, struct upg_cfg *u, int hu) {
    int f = 1;
    char k[64];
    while (sj_obj_key(j, &f, k, sizeof(k)) == 0) {
        sj_ws(j);
        if (!strcmp(k, "path") && *j->p == '"') sj_str(j, u->path, sizeof(u->path));
        else if (!strcmp(k, "host") && *j->p == '"') {
            char h[sizeof(u->host)] = "";
            sj_str(j, h, sizeof(h));
            if (h[0]) snprintf(u->host, sizeof(u->host), "%s", h);
        } else if (!strcmp(k, "headers") && *j->p == '{') xray_headers(j, u, hu);
        else sj_skip(j);
    }
}

static int sj_bool(struct sj *j);

/* streamSettings: транспорт, security и всё, что зависит от них. */
static void xray_stream(struct sj *j, struct vless_node *n) {
    int first = 1;
    char k[64];
    struct upg_cfg ws, hu;
    memset(&ws, 0, sizeof(ws));
    memset(&hu, 0, sizeof(hu));
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        if (!strcmp(k, "network")) {
            sj_str(j, n->type, sizeof(n->type));
            /* raw — каноническое имя tcp у Xray с 24.9.30; панели пишут его всё чаще. */
            if (!strcmp(n->type, "raw")) snprintf(n->type, sizeof(n->type), "tcp");
            /* websocket — второе имя ws у Xray (infra/conf: case "ws", "websocket"). */
            if (!strcmp(n->type, "websocket")) snprintf(n->type, sizeof(n->type), "ws");
        }
        else if (!strcmp(k, "tcpSettings") || !strcmp(k, "rawSettings")) {
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (strcmp(k2, "header") != 0) { sj_skip(j); continue; }
                int f3 = 1;
                char k3[64], ty[16] = "";
                while (sj_obj_key(j, &f3, k3, sizeof(k3)) == 0) {
                    if (!strcmp(k3, "type")) sj_str(j, ty, sizeof ty); else sj_skip(j);
                }
                if (!strcmp(ty, "http")) n->tcp_http = 1;
            }
        }
        else if (!strcmp(k, "wsSettings")) xray_upg(j, &ws, 0);
        else if (!strcmp(k, "httpupgradeSettings")) xray_upg(j, &hu, 1);
        else if (!strcmp(k, "security")) sj_str(j, n->security, sizeof(n->security));
        else if (!strcmp(k, "realitySettings") || !strcmp(k, "tlsSettings")) {
            /* Оба объекта несут serverName и fingerprint; publicKey и shortId бывают только
             * у reality. Разбирать их одним куском можно потому, что имена полей не спорят:
             * узел объявляет ровно один из двух. */
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "serverName")) sj_str(j, n->sni, sizeof(n->sni));
                else if (!strcmp(k2, "fingerprint")) sj_str(j, n->fp, sizeof(n->fp));
                else if (!strcmp(k2, "publicKey")) sj_str(j, n->pbk, sizeof(n->pbk));
                else if (!strcmp(k2, "shortId")) sj_str(j, n->sid, sizeof(n->sid));
                else if (!strcmp(k2, "mldsa65Verify") || !strcmp(k2, "pqv")) {
                    char *pv = malloc(4096);
                    if (pv) { pv[0] = '\0'; sj_str(j, pv, 4096); set_pqv(n, pv); free(pv); }
                    else sj_skip(j);
                }
                else if (!strcmp(k2, "pinnedPeerCertSha256") || !strcmp(k2, "pcs")) {
                    char pv[1100] = "";
                    sj_str(j, pv, sizeof pv);
                    add_pins(n, pv, 0);
                }
                else if (!strcmp(k2, "verifyPeerCertByName") || !strcmp(k2, "vcn")) {
                    char vv[300] = "";
                    sj_str(j, vv, sizeof vv);
                    set_vcn(n, vv);
                }
                else if (!strcmp(k2, "allowInsecure")) { if (sj_bool(j)) n->allow_insecure = 1; }
                else sj_skip(j);
            }
        } else if (!strcmp(k, "grpcSettings")) {
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "serviceName")) sj_str(j, n->service, sizeof(n->service));
                else sj_skip(j);
            }
        } else if (!strcmp(k, "xhttpSettings") || !strcmp(k, "splithttpSettings")) {
            /* splithttpSettings — прежнее имя того же транспорта; панели с ним ещё живут. */
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "path")) sj_str(j, n->path, sizeof(n->path));
                else if (!strcmp(k2, "mode")) sj_str(j, n->mode, sizeof(n->mode));
                /* В конфигурации это поле лежит прямо здесь, а не в `extra`: `extra` — форма
                 * ССЫЛКИ, в которую те же настройки заворачивают, когда конфигурации нет. */
                else if (!strcmp(k2, "xPaddingBytes")) {
                    char pb[32];
                    sj_str(j, pb, sizeof(pb));
                    pad_range(n, pb);
                }
                else if (!strcmp(k2, "extra")) {
                    /* Вложенный extra (форма ссылки внутри конфига): тот же просмотр, что у ссылки. */
                    const char *b = j->p;
                    sj_skip(j);
                    size_t l = (size_t)(j->p - b);
                    char *cp = malloc(l + 1);
                    if (cp) { memcpy(cp, b, l); cp[l] = 0; parse_extra(n, cp); free(cp); }
                }
                else if (!strcmp(k2, "downloadSettings") || !strcmp(k2, "sessionIDPlacement") ||
                         !strcmp(k2, "seqPlacement") || !strcmp(k2, "uplinkDataPlacement") ||
                         !strcmp(k2, "xPaddingPlacement") || !strcmp(k2, "xPaddingMethod")) {
                    sj_ws(j);
                    if (*j->p == '"' && j->p[1] == '"') { sj_skip(j); }
                    else if (!strncmp(j->p, "null", 4)) sj_skip(j);
                    else { n->xh_extra = 1; sj_skip(j); }
                }
                else if (!strcmp(k2, "xPaddingObfsMode")) { if (sj_bool(j)) n->xh_extra = 1; }
                else sj_skip(j);
            }
        } else sj_skip(j);
    }
    const struct upg_cfg *u = !strcmp(n->type, "ws") ? &ws : !strcmp(n->type, "httpupgrade") ? &hu : NULL;
    if (u) {
        snprintf(n->path, sizeof(n->path), "%s", u->path);
        snprintf(n->http_host, sizeof(n->http_host), "%s", u->host);
        snprintf(n->headers, sizeof(n->headers), "%s", u->headers);
        n->headers_bad = u->bad;
    }
}

/* settings исходящего vless: vnext[0] — адрес, порт и первый пользователь.
 *
 * Именно первый и только он: подписка описывает узел для ОДНОГО человека, и второго
 * пользователя в ней не бывает. Появится — возьмём первого и не станем притворяться, что
 * умеем больше. */
static void json_encryption(struct sj *j, struct vless_node *n) {
    char *ev = malloc(4096);
    if (!ev) { sj_skip(j); return; }
    ev[0] = '\0';
    if (sj_str(j, ev, 4096) == 0) set_encryption(n, ev);
    free(ev);
}

static void xray_settings(struct sj *j, struct vless_node *n) {
    int first = 1;
    char k[64];
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        /* Упрощённая форма исходящего (Xray 25+): address, port, id, flow, encryption прямо в settings,
         * без vnext и users. */
        if (!strcmp(k, "address")) { sj_str(j, n->host, sizeof(n->host)); continue; }
        if (!strcmp(k, "id")) { sj_str(j, n->uuid, sizeof(n->uuid)); continue; }
        if (!strcmp(k, "flow")) { sj_str(j, n->flow, sizeof(n->flow)); continue; }
        if (!strcmp(k, "encryption")) { json_encryption(j, n); continue; }
        if (!strcmp(k, "port")) {
            sj_ws(j);
            char num[16];
            if (*j->p == '"') sj_str(j, num, sizeof(num));
            else {
                size_t i = 0;
                while (*j->p >= '0' && *j->p <= '9' && i + 1 < sizeof(num)) num[i++] = *j->p++;
                num[i] = '\0';
                if (!i) sj_skip(j);
            }
            n->port = port_of(num);
            continue;
        }
        if (strcmp(k, "vnext") != 0) { sj_skip(j); continue; }
        int fa = 1, taken = 0;
        while (sj_arr_next(j, &fa) == 0) {
            if (taken) { sj_skip(j); continue; }
            taken = 1;
            int fo = 1;
            char k2[64];
            while (sj_obj_key(j, &fo, k2, sizeof(k2)) == 0) {
                if (!strcmp(k2, "address")) sj_str(j, n->host, sizeof(n->host));
                else if (!strcmp(k2, "port")) {
                    sj_ws(j);
                    char num[16];
                    /* Число или число строкой: панели пишут и так, и так. Прочее — брак,
                     * пропускается как значение, чтобы разбор не разъехался по объекту. */
                    if (*j->p == '"') sj_str(j, num, sizeof(num));
                    else {
                        size_t i = 0;
                        while (*j->p >= '0' && *j->p <= '9' && i + 1 < sizeof(num))
                            num[i++] = *j->p++;
                        num[i] = '\0';
                        if (!i) sj_skip(j);
                    }
                    n->port = port_of(num);
                } else if (!strcmp(k2, "users")) {
                    int fu = 1, u_taken = 0;
                    while (sj_arr_next(j, &fu) == 0) {
                        if (u_taken) { sj_skip(j); continue; }
                        u_taken = 1;
                        int fu2 = 1;
                        char k3[64];
                        while (sj_obj_key(j, &fu2, k3, sizeof(k3)) == 0) {
                            if (!strcmp(k3, "id")) sj_str(j, n->uuid, sizeof(n->uuid));
                            else if (!strcmp(k3, "flow")) sj_str(j, n->flow, sizeof(n->flow));
                            else if (!strcmp(k3, "encryption")) json_encryption(j, n);
                            else sj_skip(j);
                        }
                    }
                } else sj_skip(j);
            }
        }
    }
}

/* ---- sing-box: outbounds с type=vless ---------------------------------------------------------
 *
 * Панели, отдающие конфиг sing-box (клиент SFI, Hiddify, Karing), кладут узлы в тот же массив
 * `outbounds`, что и Xray, но плоско: type/tag/server/server_port/uuid/flow и объекты tls и transport.
 * Отличия от Xray, из-за которых нужен отдельный разбор: имя вида — type, а не protocol; порт — число
 * server_port; TLS — объект с вложенными utls и reality; в transport заголовок Host — строка или
 * массив строк. Ранние данные ws: max_early_data + early_data_header_name; при имени
 * Sec-WebSocket-Protocol это `?ed=N` Xray (наш ws так и умеет), при пустом sing-box кладёт данные в
 * путь — форма, которой у Xray нет, и мы ранние данные тогда не включаем (соединение сработает и без
 * них: сервер sing-box принимает обычный запрос). */
/* Дописать «Имя: значение\n» в буфер заголовков; -1, если не влезло или имя пусто. Без snprintf: он
 * предупреждает об усечении там, где усечение мы сами исключили проверкой длины. */
static int hdr_append(char *dst, size_t cap, const char *k, const char *v) {
    size_t o = strlen(dst), kn = strlen(k), vn = strlen(v);
    if (!kn || o + kn + vn + 4 >= cap) return -1;
    memcpy(dst + o, k, kn);
    dst[o + kn] = ':'; dst[o + kn + 1] = ' ';
    memcpy(dst + o + kn + 2, v, vn);
    dst[o + kn + 2 + vn] = '\n'; dst[o + kn + 3 + vn] = '\0';
    return 0;
}

static uint16_t port_of_num(long v) { return (v > 0 && v < 65536) ? (uint16_t)v : 0; }

static int sj_bool(struct sj *j) {
    sj_ws(j);
    if (!strncmp(j->p, "true", 4)) { j->p += 4; return 1; }
    if (!strncmp(j->p, "false", 5)) { j->p += 5; return 0; }
    sj_skip(j);
    return 0;
}

/* Число: либо 123, либо "123". */
static long sj_num(struct sj *j) {
    sj_ws(j);
    char b[24] = "";
    if (*j->p == '"') sj_str(j, b, sizeof b);
    else { size_t i = 0; while (*j->p >= '0' && *j->p <= '9' && i + 1 < sizeof b) b[i++] = *j->p++; b[i] = 0; if (!i) sj_skip(j); }
    return atol(b);
}

struct sb_ws { long ed; char ed_hdr[40]; };

static void sb_tls(struct sj *j, struct vless_node *n, int *enabled, int *reality) {
    int f = 1;
    char k[64];
    while (sj_obj_key(j, &f, k, sizeof k) == 0) {
        if (!strcmp(k, "enabled")) *enabled = sj_bool(j);
        else if (!strcmp(k, "server_name")) sj_str(j, n->sni, sizeof n->sni);
        else if (!strcmp(k, "insecure")) { if (sj_bool(j)) n->allow_insecure = 1; }
        else if (!strcmp(k, "certificate_public_key_sha256")) {
            /* Массив строк base64: SHA-256 от SubjectPublicKeyInfo. Строка вместо массива — тоже. */
            char pv[80];
            int fa = 1;
            int r = sj_arr_next(j, &fa);
            if (r == 0) {
                do { pv[0] = '\0'; sj_str(j, pv, sizeof pv); add_pins(n, pv, 1); } while (sj_arr_next(j, &fa) == 0);
            } else if (r < 0) { pv[0] = '\0'; sj_str(j, pv, sizeof pv); add_pins(n, pv, 1); }
        }
        else if (!strcmp(k, "utls")) {
            int f2 = 1, on = 1;
            char k2[64], fp[sizeof n->fp] = "";
            while (sj_obj_key(j, &f2, k2, sizeof k2) == 0) {
                if (!strcmp(k2, "enabled")) on = sj_bool(j);
                else if (!strcmp(k2, "fingerprint")) sj_str(j, fp, sizeof fp);
                else sj_skip(j);
            }
            if (on && fp[0]) snprintf(n->fp, sizeof n->fp, "%s", fp);
        } else if (!strcmp(k, "reality")) {
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof k2) == 0) {
                if (!strcmp(k2, "enabled")) *reality = sj_bool(j);
                else if (!strcmp(k2, "public_key")) sj_str(j, n->pbk, sizeof n->pbk);
                else if (!strcmp(k2, "short_id")) sj_str(j, n->sid, sizeof n->sid);
                else sj_skip(j);
            }
        } else sj_skip(j);
    }
}

static void sb_transport(struct sj *j, struct vless_node *n, struct sb_ws *w, struct upg_cfg *u) {
    int f = 1;
    char k[64];
    while (sj_obj_key(j, &f, k, sizeof k) == 0) {
        if (!strcmp(k, "type")) {
            sj_str(j, n->type, sizeof n->type);
            if (!strcmp(n->type, "websocket")) snprintf(n->type, sizeof n->type, "ws");
        }
        else if (!strcmp(k, "path")) sj_str(j, u->path, sizeof u->path);
        else if (!strcmp(k, "host")) {
            sj_ws(j);
            if (*j->p == '[') { int fa = 1; char h[sizeof u->host]; int got = 0;
                while (sj_arr_next(j, &fa) == 0) { if (got++) sj_skip(j); else sj_str(j, h, sizeof h); }
                if (got) snprintf(u->host, sizeof u->host, "%s", h); }
            else sj_str(j, u->host, sizeof u->host);
        }
        else if (!strcmp(k, "service_name")) sj_str(j, n->service, sizeof n->service);
        else if (!strcmp(k, "max_early_data")) w->ed = sj_num(j);
        else if (!strcmp(k, "early_data_header_name")) sj_str(j, w->ed_hdr, sizeof w->ed_hdr);
        else if (!strcmp(k, "headers")) {
            int f2 = 1;
            char k2[64];
            while (sj_obj_key(j, &f2, k2, sizeof k2) == 0) {
                sj_ws(j);
                char v[sizeof u->host] = "";
                if (*j->p == '[') { int fa = 1, got = 0;
                    while (sj_arr_next(j, &fa) == 0) { if (got++) sj_skip(j); else sj_str(j, v, sizeof v); } }
                else if (*j->p == '"') sj_str(j, v, sizeof v);
                else { sj_skip(j); u->bad = 1; continue; }
                if (ci_eq(k2, "host")) { if (!u->host[0]) snprintf(u->host, sizeof u->host, "%s", v); }
                else {
                    if (hdr_append(u->headers, sizeof u->headers, k2, v) != 0) u->bad = 1;
                }
            }
        } else sj_skip(j);
    }
}

/* Один outbound sing-box уже прочитан в поля; здесь — свести в узел. Вызывается из xray_outbound,
 * когда встретился ключ type (у Xray его на этом уровне нет). */
static void sb_outbound_body(struct sj *j, struct vless_node *n, char *proto, size_t proto_n) {
    /* Возврат сюда после первого ключа невозможен: разбор идёт единым проходом в xray_outbound,
     * поэтому функция читает остаток объекта сама. */
    int first = 1, tls_on = 0, reality = 0;
    char k[64];
    struct sb_ws w; struct upg_cfg u;
    memset(&w, 0, sizeof w); memset(&u, 0, sizeof u);
    while (sj_obj_key(j, &first, k, sizeof k) == 0) {
        if (!strcmp(k, "type")) sj_str(j, proto, proto_n);
        else if (!strcmp(k, "tag")) { sj_str(j, n->name, sizeof n->name); utf8_trim_tail(n->name); }
        else if (!strcmp(k, "server")) sj_str(j, n->host, sizeof n->host);
        else if (!strcmp(k, "server_port")) n->port = port_of_num(sj_num(j));
        else if (!strcmp(k, "uuid")) sj_str(j, n->uuid, sizeof n->uuid);
        else if (!strcmp(k, "flow")) sj_str(j, n->flow, sizeof n->flow);
        else if (!strcmp(k, "tls")) sb_tls(j, n, &tls_on, &reality);
        else if (!strcmp(k, "transport")) sb_transport(j, n, &w, &u);
        else sj_skip(j);
    }
    snprintf(n->security, sizeof n->security, "%s", reality ? "reality" : tls_on ? "tls" : "none");
    if (!n->type[0]) snprintf(n->type, sizeof n->type, "tcp");
    if (!strcmp(n->type, "ws") && w.ed > 0 && !strcmp(w.ed_hdr, "Sec-WebSocket-Protocol") && !strchr(u.path, '?')) {
        size_t o = strlen(u.path);
        if (!o) { u.path[0] = '/'; u.path[1] = 0; o = 1; }
        snprintf(u.path + o, sizeof u.path - o, "?ed=%ld", w.ed);
    }
    if (!strcmp(n->type, "ws") || !strcmp(n->type, "httpupgrade")) {
        snprintf(n->path, sizeof n->path, "%s", u.path);
        snprintf(n->http_host, sizeof n->http_host, "%s", u.host);
        snprintf(n->headers, sizeof n->headers, "%s", u.headers);
        n->headers_bad = u.bad;
    }
}

/* Один outbound. 1 — это узел vless и он записан в n, 0 — не наш. */
static int xray_outbound(struct sj *j, struct vless_node *n) {
    memset(n, 0, sizeof(*n));
    /* Умолчание транспорта — tcp, как у ссылки: конфиг без streamSettings или без network
     * законен (так и подразумевает Xray), а пустое слово давало «транспорт  не поддержан». */
    snprintf(n->type, sizeof(n->type), "tcp");
    int first = 1, is_vless = 0;
    char k[64], proto[32] = "";
    /* Какой это формат — Xray (protocol) или sing-box (type)? Предпросмотр ключей верхнего уровня, как
     * у remarks: порядок ключей не задан, а разбор идёт единым проходом. */
    {
        const char *save = j->p;
        int f0 = 1, has_protocol = 0, has_type = 0;
        char k0[64];
        while (sj_obj_key(j, &f0, k0, sizeof k0) == 0) {
            if (!strcmp(k0, "protocol")) has_protocol = 1;
            else if (!strcmp(k0, "type")) has_type = 1;
            sj_skip(j);
        }
        j->p = save;
        if (has_type && !has_protocol) {
            sb_outbound_body(j, n, proto, sizeof proto);
            return !strcmp(proto, "vless");
        }
    }
    /* Порядок ключей в JSON не задан, поэтому protocol может оказаться ПОСЛЕ settings.
     * Значит читаем всё, а решаем в конце: разбор чужого исходящего в свободные поля никому
     * не вредит, потому что узел всё равно не будет взят. */
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        if (!strcmp(k, "protocol")) sj_str(j, proto, sizeof(proto));
        /* tag из конфигурации Xray обрезается тем же байтовым пределом, что и имя из
         * фрагмента ссылки, — и рвётся так же. */
        else if (!strcmp(k, "tag")) { sj_str(j, n->name, sizeof(n->name)); utf8_trim_tail(n->name); }
        else if (!strcmp(k, "settings")) xray_settings(j, n);
        else if (!strcmp(k, "streamSettings")) xray_stream(j, n);
        else sj_skip(j);
    }
    is_vless = !strcmp(proto, "vless");
    return is_vless;
}

/* Имя, которое панель показала человеку, лежит в remarks КОНФИГА, а не в tag исходящего.
 *
 * Снято на живой панели (ответ клиенту Happ): семь конфигов, у пяти из них tag исходящего —
 * одно и то же слово «proxy», а различает их только remarks («Германия», «Финляндия», …).
 * У остальных двух tag вида «tl-8-1-43al6bgvgg4» — со СЛУЧАЙНЫМ суффиксом, который панель
 * меняет на каждый запрос. То есть на этом формате имя из tag даёт либо пять одинаковых
 * «proxy», либо имя, которое меняется само по себе при каждом обновлении подписки, — и
 * человек в списке узлов splify2 не может ни отличить их друг от друга, ни узнать вчерашний.
 *
 * ПРЕДПРОСМОТР, А НЕ ЧТЕНИЕ ПО ХОДУ. В ответе панели remarks стоит ПОСЛЕ outbounds: пока
 * поток дойдёт до него, узлы уже записаны и переименовывать было бы нечего — указатель
 * назад не отматывается. Поэтому объект конфига сначала пробегается на один только remarks
 * (sj_skip ничего не копирует), а потом разбирается заново с начала. Второго прохода по
 * всему тексту подписки при этом нет: пробег ограничен одним конфигом.
 *
 * Процентная форма здесь НЕ раскрывается, в отличие от имени из #фрагмента ссылки: remarks —
 * поле JSON, и «%2F» в нём означает ровно эти три знака. Тот же довод, что у tag выше. */
static void xray_remarks(struct sj *j, char *out, size_t n) {
    out[0] = '\0';
    const char *save = j->p;
    int first = 1;
    char k[64];
    while (sj_obj_key(j, &first, k, sizeof(k)) == 0) {
        if (!strcmp(k, "remarks")) { sj_str(j, out, n); utf8_trim_tail(out); }
        else sj_skip(j);
    }
    j->p = save;
}

/* Имя узла из remarks конфига. ord — какой это по счёту исходящий vless В ЭТОМ конфиге.
 *
 * Второму и дальше приписывается номер: конфиг с балансировщиком несёт два узла — основной
 * и запасной, — и без номера оба назывались бы одинаково. Номер, а не tag: tag у таких
 * исходящих как раз и есть та случайная строка, от которой имя уводится.
 *
 * Номер в скобках, а не через «#»: панели сами нумеруют узлы решёткой («Мобильная связь #1»),
 * и «Мобильная связь #1 #2» читается как опечатка, а «Мобильная связь #1 (2)» — как второй
 * узел той же строки подписки.
 *
 * Обрезка возможна только у remarks длиной почти в весь буфер имени; тогда номер до имени
 * не доедет и два узла снова совпадут. Это лучше, чем ради номера отрезать человеку имя. */
static void xray_name(struct vless_node *nd, const char *remarks, size_t ord) {
    if (ord == 0) snprintf(nd->name, sizeof(nd->name), "%s", remarks);
    else snprintf(nd->name, sizeof(nd->name), "%s (%zu)", remarks, ord + 1);
    utf8_trim_tail(nd->name);
}

/* Конфиг целиком: массив конфигов или один. Возвращает число ПРИГОДНЫХ узлов. */
static size_t parse_xray(const char *text, struct vless_node *out, size_t max,
                         struct vless_sub_stats *st) {
    struct sj j = { text };
    size_t n = 0;
    sj_ws(&j);
    /* Один конфиг заворачивается в массив из одного: дальше путь общий. */
    int wrapped = (*j.p == '{');
    int fa = 1;
    if (wrapped) fa = 0;                    /* массива нет — сразу разбираем объект */
    for (;;) {
        if (!wrapped) {
            int r = sj_arr_next(&j, &fa);
            if (r != 0) break;
        }
        const char *cfg_before = j.p;
        /* Тело одного конфига: узлы — из outbounds, имя им — из remarks (xray_remarks). */
        char remarks[sizeof(((struct vless_node *)0)->name)];
        xray_remarks(&j, remarks, sizeof(remarks));
        size_t ord = 0;
        int fc = 1;
        char k[64];
        int seen_ob = 0;
        while (sj_obj_key(&j, &fc, k, sizeof(k)) == 0) {
            if (strcmp(k, "outbounds") != 0) { sj_skip(&j); continue; }
            seen_ob = 1;
            int fo = 1;
            while (sj_arr_next(&j, &fo) == 0) {
                struct vless_node node;
                const char *before = j.p;
                int ours = xray_outbound(&j, &node);
                if (j.p == before) break;               /* разбор не двинулся — уходим */
                if (!ours) continue;
                /* До проверки пригодности: имя уходит и в список узлов, и в объяснение
                 * пропуска (skip_note берёт его как пример), а человеку в обоих местах
                 * нужно одно и то же слово — то, которое он видит в панели. */
                if (remarks[0]) xray_name(&node, remarks, ord);
                ord++;
                if (n >= max) {
                    /* Мест больше нет. Считаем как пропущенный, а не теряем молча: то же
                     * обещание, что у списка ссылок — арифметика обязана сходиться. */
                    skip_note(st, &node, "узлов больше, чем помещается");
                    continue;
                }
                if (node_usable(&node) == 0) out[n++] = node;
                else skip_note(st, &node, node.skip_reason);
            }
        }
        (void)seen_ob;
        if (wrapped) break;
        if (j.p == cfg_before) break;                   /* конфиг не разобрался — не крутимся */
    }
    return n;
}

/* ---- Clash / Mihomo: proxies с type: vless -------------------------------------------------------
 *
 * Панели отдают клиентам Clash YAML: список `proxies:`, у каждого узла плоский набор ключей и вложенные
 * *-opts (ws-opts, reality-opts, grpc-opts, xhttp-opts). Записаны бывают двумя способами — блоком
 * (`- name: x` и ключи с отступом) и потоком (`- {name: x, type: vless, reality-opts: {public-key: k}}`,
 * так пишут конвертеры), и разбор обязан уметь оба.
 *
 * Общий YAML-разбор (src/lib/ynode.c) здесь не берётся: он отказывает на якорях и алиасах целиком, а
 * подписка с якорем в блоке proxy-groups не должна терять узлы; и он тянет libyaml в стенд, который
 * проверяет чужой текст в одиночку. Вместо него — разбор ровно той формы, которую ждём: каждый узел
 * «сплющивается» в пары путь=значение (`reality-opts.public-key`, `ws-opts.headers.Host`, `alpn.0`), а
 * узел строится по путям. Что не разобралось (якорь-алиас `*a`, многострочные скаляры) — значение
 * пропускается, узел получает то, что удалось. Якоря `&a` перед значением отбрасываются. */
#define YF_MAX 96
struct yflat {
    char buf[12288];
    size_t used, n;
    struct { const char *k, *v; } kv[YF_MAX];
};

static void yf_add(struct yflat *f, const char *path, size_t pn, const char *val, size_t vn) {
    if (f->n >= YF_MAX || f->used + pn + vn + 2 > sizeof f->buf) return;
    char *k = f->buf + f->used;
    memcpy(k, path, pn); k[pn] = 0;
    char *v = k + pn + 1;
    memcpy(v, val, vn); v[vn] = 0;
    f->used += pn + vn + 2;
    f->kv[f->n].k = k; f->kv[f->n].v = v; f->n++;
}

static const char *yf_get(const struct yflat *f, const char *path) {
    for (size_t i = 0; i < f->n; i++) if (!strcmp(f->kv[i].k, path)) return f->kv[i].v;
    return NULL;
}
/* Без учёта регистра: Host/host в headers. */
static const char *yf_geti(const struct yflat *f, const char *path) {
    for (size_t i = 0; i < f->n; i++) if (ci_eq(f->kv[i].k, path)) return f->kv[i].v;
    return NULL;
}

/* Скаляр с p: в кавычках или простой. flow != 0 — простой кончается на , } ]. Возвращает указатель за
 * скаляром; значение — в out (раскавыченное), длина в *on. */
static const char *y_scalar(const char *p, const char *end, int flow, char *out, size_t cap, size_t *on) {
    size_t o = 0;
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    /* Якорь/тег перед значением. */
    while (p < end && (*p == '&' || *p == '!')) { while (p < end && *p != ' ' && *p != '\t') p++; while (p < end && (*p == ' ' || *p == '\t')) p++; }
    if (p < end && (*p == '"' || *p == '\'')) {
        char q = *p++;
        while (p < end && *p != q) {
            if (q == '"' && *p == '\\' && p + 1 < end) p++;
            else if (q == '\'' && *p == '\'' && p + 1 < end && p[1] == '\'') p++;
            if (o + 1 < cap) out[o++] = *p;
            p++;
        }
        if (p < end) p++;
    } else {
        const char *st0 = p;
        while (p < end && *p != '\n' && *p != '\r') {
            if (flow && (*p == ',' || *p == '}' || *p == ']')) break;
            /* flow == 2 — ключ: кончается на «:» с пробелом (или концом) следом. */
            if (flow == 2 && *p == ':' && (p + 1 >= end || p[1] == ' ' || p[1] == '\n' || p[1] == '\r')) break;
            if (*p == '#' && p > st0 && (p[-1] == ' ' || p[-1] == '\t')) break;
            if (o + 1 < cap) out[o++] = *p;
            p++;
        }
        while (o && (out[o - 1] == ' ' || out[o - 1] == '\t')) o--;
    }
    out[o] = 0;
    *on = o;
    return p;
}

static const char *y_flow(struct yflat *f, const char *p, const char *end, char *path, size_t pn, int depth);

/* Значение в потоковой записи: {…}, […] или скаляр. */
static const char *y_flow_val(struct yflat *f, const char *p, const char *end, char *path, size_t pn, int depth) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    if (p < end && (*p == '{' || *p == '[')) return y_flow(f, p, end, path, pn, depth + 1);
    char v[3300];
    size_t vn;
    p = y_scalar(p, end, 1, v, sizeof v, &vn);
    if (v[0] != '*') yf_add(f, path, pn, v, vn);
    return p;
}

static const char *y_flow(struct yflat *f, const char *p, const char *end, char *path, size_t pn, int depth) {
    if (depth > 6 || p >= end) return end;
    char open = *p++;
    unsigned idx = 0;
    for (;;) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',')) p++;
        if (p >= end) return end;
        if (*p == '}' || *p == ']') return p + 1;
        char np[200];
        size_t npn;
        if (open == '{') {
            char key[96];
            size_t kn;
            p = y_scalar(p, end, 2, key, sizeof key, &kn);
            while (p < end && (*p == ' ' || *p == '\t')) p++;
            if (p < end && *p == ':') p++;
            npn = (size_t)snprintf(np, sizeof np, "%.*s%s%s", (int)pn, path, pn ? "." : "", key);
        } else {
            npn = (size_t)snprintf(np, sizeof np, "%.*s%s%u", (int)pn, path, pn ? "." : "", idx++);
        }
        if (npn >= sizeof np) npn = sizeof np - 1;
        p = y_flow_val(f, p, end, np, npn, depth);
    }
}

/* Строка блока: отступ и текст без него. */
static const char *y_line(const char *p, const char *end, size_t *ind, const char **e) {
    size_t i = 0;
    while (p + i < end && p[i] == ' ') i++;
    const char *s = p + i, *q = s;
    while (q < end && *q != '\n') q++;
    *ind = i;
    *e = q;
    return s;
}

/* Один узел блока: p — начало строки «- …» (отступ dash); результат — начало строки после узла. */
static const char *y_item(struct yflat *f, const char *p, const char *end, size_t dash) {
    struct lvl { size_t ind; char path[200]; } st[6];
    int sp = 1, first = 1;
    st[0].ind = 0; st[0].path[0] = 0;
    char lastkey[200] = "";
    unsigned seq = 0;
    while (p < end) {
        size_t ind;
        const char *e;
        const char *s = y_line(p, end, &ind, &e);
        const char *next = e < end ? e + 1 : e;
        if (e > s && e[-1] == '\r') e--;
        if (s >= e || *s == '#' || (e - s >= 3 && !strncmp(s, "---", 3))) { p = next; continue; }
        if (first) {
            first = 0;
            s += 1; ind += 1;                                   /* тире */
            while (s < e && *s == ' ') { s++; ind++; }
            if (s < e && *s == '{') {
                char none[1] = "";
                y_flow(f, s, end, none, 0, 0);
                int d = 0;
                const char *q = s;
                for (; q < end; q++) { if (*q == '{') d++; else if (*q == '}' && --d == 0) break; }
                while (q < end && *q != '\n') q++;
                return q < end ? q + 1 : q;
            }
        } else if (ind <= dash) {
            if (!(ind == dash && 0)) return p;
        }
        if (!first && ind > dash && (*s == '-' && (e - s == 1 || s[1] == ' '))) {
            char v[3300];
            size_t vn;
            y_scalar(s + 1, e, 0, v, sizeof v, &vn);
            char np[200];
            int n2 = snprintf(np, sizeof np, "%s.%u", lastkey, seq++);
            if (lastkey[0] && n2 > 0 && n2 < (int)sizeof np && v[0] != '*') yf_add(f, np, (size_t)n2, v, vn);
            p = next;
            continue;
        }
        while (sp > 1 && st[sp - 1].ind >= ind) sp--;
        char key[96];
        size_t kn;
        const char *c = y_scalar(s, e, 2, key, sizeof key, &kn);
        while (c < e && (*c == ' ' || *c == '\t')) c++;
        if (c >= e || *c != ':') { p = next; continue; }
        c++;
        char np[200];
        int n2 = snprintf(np, sizeof np, "%s%s%s", st[sp - 1].path, st[sp - 1].path[0] ? "." : "", key);
        if (n2 <= 0 || n2 >= (int)sizeof np) { p = next; continue; }
        while (c < e && (*c == ' ' || *c == '\t')) c++;
        if (c >= e || *c == '#') {
            snprintf(lastkey, sizeof lastkey, "%s", np);
            seq = 0;
            if (sp < 6) { st[sp].ind = ind; snprintf(st[sp].path, sizeof st[sp].path, "%s", np); sp++; }
        } else if (*c == '{' || *c == '[') {
            y_flow(f, c, end, np, (size_t)n2, 0);
        } else {
            char v[3300];
            size_t vn;
            y_scalar(c, e, 0, v, sizeof v, &vn);
            if (v[0] != '*') yf_add(f, np, (size_t)n2, v, vn);
        }
        p = next;
    }
    return p;
}

/* Плоский узел → узел vless. 1 — это vless и он записан в n. */
static int clash_node(const struct yflat *f, struct vless_node *n) {
    memset(n, 0, sizeof *n);
    const char *v;
    if (!(v = yf_get(f, "type")) || strcmp(v, "vless")) return 0;
    snprintf(n->type, sizeof n->type, "tcp");
    if ((v = yf_get(f, "name"))) { set_field(n->name, sizeof n->name, v, strlen(v)); utf8_trim_tail(n->name); }
    if ((v = yf_get(f, "server"))) set_field(n->host, sizeof n->host, v, strlen(v));
    if ((v = yf_get(f, "port"))) n->port = port_of(v);
    if ((v = yf_get(f, "uuid"))) set_field(n->uuid, sizeof n->uuid, v, strlen(v));
    if ((v = yf_get(f, "flow"))) set_field(n->flow, sizeof n->flow, v, strlen(v));
    if ((v = yf_get(f, "servername")) || (v = yf_get(f, "sni"))) set_field(n->sni, sizeof n->sni, v, strlen(v));
    if ((v = yf_get(f, "client-fingerprint"))) set_field(n->fp, sizeof n->fp, v, strlen(v));
    /* Clash/mihomo: `fingerprint` — SHA-256 сертификата узла (то же, что pinnedPeerCertSha256 Xray),
     * `skip-cert-verify` — allowInsecure. */
    if ((v = yf_get(f, "fingerprint")) && v[0]) add_pins(n, v, 0);
    if ((v = yf_get(f, "skip-cert-verify")) && truthy_flag(v)) n->allow_insecure = 1;
    const char *pbk = yf_get(f, "reality-opts.public-key");
    if (pbk) {
        set_field(n->pbk, sizeof n->pbk, pbk, strlen(pbk));
        if ((v = yf_get(f, "reality-opts.short-id"))) set_field(n->sid, sizeof n->sid, v, strlen(v));
        if ((v = yf_get(f, "reality-opts.mldsa65-verify")) || (v = yf_get(f, "reality-opts.pqv"))) set_pqv(n, v);
        snprintf(n->security, sizeof n->security, "reality");
    } else {
        v = yf_get(f, "tls");
        snprintf(n->security, sizeof n->security, "%s", v && (!strcmp(v, "true") || !strcmp(v, "True")) ? "tls" : "none");
    }
    if ((v = yf_get(f, "encryption"))) set_encryption(n, v);
    const char *net = yf_get(f, "network");
    if (net) {
        if (!strcmp(net, "raw")) net = "tcp";
        set_field(n->type, sizeof n->type, net, strlen(net));
    }
    const char *upg = yf_get(f, "ws-opts.v2ray-http-upgrade");
    if (!strcmp(n->type, "ws") && upg && !strcmp(upg, "true")) snprintf(n->type, sizeof n->type, "httpupgrade");
    if (!strcmp(n->type, "ws") || !strcmp(n->type, "httpupgrade")) {
        struct upg_cfg u;
        memset(&u, 0, sizeof u);
        if ((v = yf_get(f, "ws-opts.path"))) set_field(u.path, sizeof u.path, v, strlen(v));
        if ((v = yf_geti(f, "ws-opts.headers.host"))) set_field(u.host, sizeof u.host, v, strlen(v));
        for (size_t i = 0; i < f->n; i++) {
            const char *k = f->kv[i].k;
            if (strncmp(k, "ws-opts.headers.", 16) != 0 || ci_eq(k + 16, "host")) continue;
            if (hdr_append(u.headers, sizeof u.headers, k + 16, f->kv[i].v) != 0) u.bad = 1;
        }
        const char *ed = yf_get(f, "ws-opts.max-early-data"), *eh = yf_get(f, "ws-opts.early-data-header-name");
        if (ed && atol(ed) > 0 && eh && !strcmp(eh, "Sec-WebSocket-Protocol") && !strchr(u.path, '?')) {
            size_t o = strlen(u.path);
            if (!o) { u.path[0] = '/'; u.path[1] = 0; o = 1; }
            snprintf(u.path + o, sizeof u.path - o, "?ed=%ld", atol(ed));
        }
        snprintf(n->path, sizeof n->path, "%s", u.path);
        snprintf(n->http_host, sizeof n->http_host, "%s", u.host);
        snprintf(n->headers, sizeof n->headers, "%s", u.headers);
        n->headers_bad = u.bad;
    } else if (!strcmp(n->type, "grpc")) {
        if ((v = yf_get(f, "grpc-opts.grpc-service-name"))) set_field(n->service, sizeof n->service, v, strlen(v));
    } else if (!strcmp(n->type, "xhttp")) {
        if ((v = yf_get(f, "xhttp-opts.path"))) set_field(n->path, sizeof n->path, v, strlen(v));
        if ((v = yf_get(f, "xhttp-opts.mode"))) set_field(n->mode, sizeof n->mode, v, strlen(v));
        if ((v = yf_get(f, "xhttp-opts.x-padding-bytes"))) pad_range(n, v);
    }
    return 1;
}

/* Clash YAML целиком. Возвращает число пригодных узлов; foreign — узлы других протоколов (в st). */
static size_t parse_clash(const char *text, struct vless_node *out, size_t max, struct vless_sub_stats *st) {
    const char *end = text + strlen(text), *p = text;
    size_t n = 0, dash = 0;
    int in_list = 0;
    struct yflat *f = malloc(sizeof *f);
    if (!f) return 0;
    while (p < end) {
        size_t ind;
        const char *e;
        const char *s = y_line(p, end, &ind, &e);
        const char *next = e < end ? e + 1 : e;
        if (!in_list) {
            if (ind == 0 && (!strncmp(s, "proxies:", 8) || !strncmp(s, "Proxy:", 6))) {
                const char *c = s + (s[0] == 'p' ? 8 : 6);
                while (c < e && *c == ' ') c++;
                if (c < e && *c != '#') break;                 /* «proxies: []» и т.п.: узлов нет */
                in_list = 1;
                dash = (size_t)-1;
            }
            p = next;
            continue;
        }
        if (s >= e || *s == '#') { p = next; continue; }
        if (ind == 0 && *s != '-') break;                     /* следующий ключ верхнего уровня */
        if (*s == '-' && (s + 1 == e || s[1] == ' ')) {
            if (dash == (size_t)-1) dash = ind;
            if (ind != dash) { p = next; continue; }
            f->n = 0; f->used = 0;
            p = y_item(f, p, end, dash);
            struct vless_node node;
            if (!clash_node(f, &node)) { if (st) st->foreign++; continue; }
            if (n >= max) { skip_note(st, &node, "узлов больше, чем помещается"); continue; }
            if (node_usable(&node) == 0) out[n++] = node;
            else skip_note(st, &node, node.skip_reason);
            continue;
        }
        p = next;
    }
    free(f);
    return n;
}

/* Это Clash YAML? В любой строке верхнего уровня стоит «proxies:» (или «Proxy:» — прежнее имя). Список
 * ссылок и base64 такой строки не содержат: в base64 нет двоеточия. */
static int looks_clash(const char *t) {
    for (const char *p = t; *p; ) {
        if (!strncmp(p, "proxies:", 8) || !strncmp(p, "Proxy:", 6)) return 1;
        const char *nl = strchr(p, '\n');
        if (!nl) break;
        p = nl + 1;
    }
    return 0;
}

/* Предел длины ОДНОЙ ссылки подписки.
 *
 * Было 2048, и этого перестало хватать. Reality с постквантовой подписью (Xray-core 25.9+)
 * кладёт в ссылку параметр `pqv` — ПУБЛИЧНЫЙ КЛЮЧ ML-DSA-65 целиком, в base64url. Ключ
 * весит 1952 байта, в base64url это ровно 2603 знака, и вся ссылка выходит 2860 байт —
 * столько и снято на живой подписке. Подписка из одной такой ссылки давала «пригодных
 * узлов: 0» и объяснение «ссылка длиннее 2048 байт», то есть выход собрать было не из чего,
 * притом что сама подписка скачивалась и была верна.
 *
 * ЭТО ПОДПИСЬ, А НЕ ОБМЕН КЛЮЧАМИ, и путать их дорого: постквантовый обмен у Reality идёт
 * группой X25519MLKEM768 в key_share (см. reality.h), а `pqv` — совсем про другое: им
 * сервер дополнительно подписывает свой временный сертификат, и проверяет эту подпись
 * клиент: reality.c включает проверку, когда параметр задан (tls13.c → cert_reality_check_pq). Ключ
 * хранится в общей таблице (sub_intern).
 *
 * 8192, а не 4096: запас взят на вырост ключа (у ML-DSA-87 он 2592 байта, то есть 3456
 * знаков), а буфер живёт на стеке ОДНОЙ подкоманды CLI, рядом с которой уже стоят два
 * статических буфера по 256 КБ под текст подписки, — восемь килобайт здесь ничего не
 * решают. Разбор в рабочих потоках туннеля (стек 128 КБ) этот путь не проходит. */
#define SUB_LINE_MAX 8192

/* Знак, из которых состоит имя схемы: `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`
 * (RFC 3986 §3.1), с поправкой на то, что подписки пишут схемы строчными. */
static int scheme_ch(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '+' || c == '.' || c == '-';
}

/* Приклеенная без разделителя ссылка, схемы которой мы не знаем. Возвращает место самого
 * «://» приклеенной ссылки либо NULL.
 *
 * ЗАЧЕМ ЭТО ОТДЕЛЬНО ОТ РАЗДЕЛИТЕЛЯ ВЫШЕ. Разделитель отступает к началу следующей ссылки
 * по ИМЕНИ схемы из закрытого списка, и там это единственно верный способ: на паре
 * «…#one» + «vless://…» общее правило по форме отступило бы к началу «onevless» — имя,
 * правильное по форме, — и вторая ссылка перестала бы быть ссылкой vless. Список эту
 * двусмысленность решает знанием, и отбирать у него эту работу нельзя.
 *
 * Но когда список не нашёл ничего, пара всё равно склеена — просто мы не знаем, где
 * граница. Тогда единственный честный ответ не «поделим как-нибудь», а «назовём вслух»:
 * узел объявляется непригодным с причиной, в которой стоит схема приклеенной ссылки.
 * Прежде первый узел приезжал в интерфейс с чужим хвостом вместо имени, а второй исчезал,
 * не попав ни в один счётчик, и ни одно число при этом не расходилось — одна ссылка, один
 * узел (I-208, воспроизводит журнал steer#2; владелец согласился на «Б+В» в splicicd#23).
 *
 * СХЕМА ПРИ ЭТОМ НЕ НАЗЫВАЕТСЯ, И ЭТО НЕ СКРОМНОСТЬ. Назвать её по форме нельзя: отступ от
 * «://» по знакам схемы на «…#oneanytls://…» даёт «oneanytls», и сказать человеку «склейка
 * с oneanytls://» значило бы соврать с уверенным видом. Ровно та же двусмысленность, из-за
 * которой список схем и существует. Поэтому наружу идёт то, что известно точно: длина
 * хвоста и его первые байты — по ним место склейки находится в тексте подписки, а имя
 * протокола человек прочтёт там сам.
 *
 * ВТОРОЙ ПРИЗНАК — `@` В ПРИКЛЕЕННОЙ ССЫЛКЕ, и без него правило было бы вредным. Продавцы
 * пишут в имя узла адрес своего канала («#канал https://t.me/shop»), и по одной только
 * форме схемы такой узел объявлялся бы непригодным — то есть общее правило отняло бы
 * рабочие узлы у тех, у кого сегодня всё в порядке. Ссылка прокси несёт учётные данные
 * перед хостом, адрес канала — нет; этим они и различаются. Ссылки без `@` (vmess как
 * base64, ss в старой форме) в списке схем есть, значит сюда не доходят.
 *
 * Ищется ПЕРВОЕ вхождение: если склеек больше одной, назвать надо ту, что ближе к началу,
 * — с неё и потерялось. */
static const char *glued_tail(const char *b, const char *e) {
    for (const char *q = b + 1; q + 3 <= e; q++) {
        if (strncmp(q, "://", 3) != 0) continue;
        const char *sc = q;
        while (sc > b && scheme_ch(sc[-1])) sc--;
        /* Дошли до начала ссылки — это схема САМОЙ ссылки, делить нечего. */
        if (sc == b) continue;
        size_t sl = (size_t)(q - sc);
        /* Не короче двух знаков и не длиннее пятнадцати: односложное «x://» скорее
         * случайность в имени узла, чем протокол, а имён схем длиннее пятнадцати у
         * прокси не бывает. Первый знак — буква, как требует RFC 3986. */
        if (sl < 2 || sl > 15 || sc[0] < 'a' || sc[0] > 'z') continue;
        int creds = 0;
        for (const char *t = q + 3; t < e && *t != '#'; t++)
            if (*t == '@') { creds = 1; break; }
        if (!creds) continue;
        return q;
    }
    return NULL;
}

/* Одна запись о склейке. Границей служит e, а не терминатор: в ветке длины ссылка в буфер
 * не копируется, а сказать про склейку надо и там — иначе неразделённая пара и настоящая
 * длинная ссылка дают ОДИН журнал («ссылка длиннее 8191 байт»), то есть один симптом на
 * две разные починки. Ровно это и стоит второй половиной обращения steer#2. */
static void glue_note(struct vless_sub_stats *st, const char *glue, const char *e) {
    size_t tail = (size_t)(e - glue);
    size_t show = tail < 32 ? tail : 32;
    struct vless_node t;
    memset(&t, 0, sizeof t);
    snprintf(t.name, sizeof t.name, "хвост %zu байт: %.*s", tail, (int)show, glue);
    skip_note(st, &t, "ссылки склеены без разделителя");
}

/* Разобрать текст подписки (уже декодированный из base64) в массив узлов.
 * Возвращает число ПРИГОДНЫХ; остальное — в st (может быть NULL). */
size_t vless_parse_sub(const char *text, struct vless_node *out, size_t max,
                       struct vless_sub_stats *st) {
    size_t n = 0;
    if (st) memset(st, 0, sizeof(*st));
    const char *p = text;
    /* Форма определяется ПЕРВЫМ непробельным знаком, а не поиском подстроки: '[' или '{'
     * бывает только у JSON, а список ссылок с них не начинается никогда. Прежнее правило в
     * tunnel.c искало «://» и на конфиге Xray срабатывало случайно — там «https://» лежит
     * внутри настроек DNS. Случайность в распознавании чужого формата — это отказ, который
     * появится ровно тогда, когда панель уберёт одну строчку из своего конфига. */
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '[' || *p == '{') return parse_xray(p, out, max, st);
    if (looks_clash(p)) return parse_clash(p, out, max, st);
    while (*p) {
        while (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t') p++;
        if (!*p) break;
        /* Конец ссылки — перевод строки ИЛИ начало следующей схемы. Подписки часто
         * приходят без завершающего перевода, а некоторые панели склеивают ссылки без
         * разделителя вовсе; при разборе только по переводу последняя ссылка тогда
         * склеивалась со следующей и терялась молча. */
        const char *e = p;
        while (*e && *e != '\n' && *e != '\r') {
            if (e > p && !strncmp(e, "://", 3)) {
                /* Отступаем к началу схемы — по ИМЕНИ СХЕМЫ, а не по алфавиту.
                 *
                 * Отступ по алфавиту («пока слева буквы и цифры») съедал хвост имени
                 * узла: в «...#onevless://b@...» он уходил до самого '#', граница
                 * ставилась перед «onevless», и вторая ссылка начиналась со лишних
                 * букв — то есть переставала быть vless-ссылкой и уходила в чужие
                 * протоколы. На склеенной подписке так терялся КАЖДЫЙ второй узел,
                 * а первому обнулялось имя. Условие срабатывало почти всегда: имена
                 * узлов кончаются буквой или цифрой чаще, чем нет.
                 *
                 * Список отсортирован по УБЫВАНИЮ длины, и берётся первое совпадение —
                 * то есть самое длинное. Короткое имя схемы обязано проигрывать
                 * длинному, иначе граница встаёт внутри чужого слова: «ss» совпадает
                 * с хвостом самого «vless», и разбор рубил бы каждую ссылку по её же
                 * собственной схеме. По той же причине после самого длинного совпадения
                 * к более коротким не переходим: если оно указывает на начало ЭТОЙ
                 * ссылки, делить нечего.
                 *
                 * Имя узла, оканчивающееся именем схемы («...#Express» перед «ss://»),
                 * разделится верно: сравниваются ровно байты перед «://». */
                static const char *const schemes[] = {
                    "hysteria2", "wireguard", "hysteria", "trojan", "vmess",
                    "vless", "tuic", "hy2", "ssr", "ss"
                };
                const char *s2 = NULL;
                for (size_t si = 0; si < sizeof(schemes) / sizeof(*schemes); si++) {
                    size_t sl = strlen(schemes[si]);
                    if ((size_t)(e - p) < sl) continue;
                    if (strncmp(e - sl, schemes[si], sl) != 0) continue;
                    /* Строго больше: равенство означает схему САМОЙ этой ссылки. */
                    if ((size_t)(e - p) > sl) s2 = e - sl;
                    break;
                }
                if (s2) { e = s2; break; }
            }
            e++;
        }

        char line[SUB_LINE_MAX];
        size_t len = (size_t)(e - p);
        if (len >= sizeof(line)) {
            /* Ссылка длиннее буфера. Считается непригодной, а не пропадает: см. ниже —
             * счётчики обязаны сходиться с числом ссылок в тексте.
             *
             * Предел назван ЧИСЛОМ ИЗ БУФЕРА, а не переписан в строке: прежде здесь стояло
             * «длиннее 2048 байт» словами, и предел с сообщением разошлись бы при первой же
             * правке буфера — человек читал бы про 2048 там, где отказали на 8192. */
            char why[64];
            snprintf(why, sizeof why, "ссылка длиннее %zu байт", sizeof(line) - 1);
            const char *glue = strncmp(p, "vless://", 8) ? NULL : glued_tail(p, e);
            if (glue) {
                /* Склейка называется РАНЬШЕ длины: длина здесь следствие, а не причина, и
                 * человеку, у которого панель не поставила разделитель, «ссылка длиннее
                 * 8191 байт» не говорит ничего о том, что делать. */
                glue_note(st, glue, e);
            } else if (!strncmp(p, "vless://", 8)) {
                /* Пример — длина и начало адреса узла (I-209). Одна причина без измерения
                 * не отличает ссылку чуть длиннее предела (поднимать предел) от блоба на
                 * десятки килобайт (искать разделитель), а skip_note схлопывает причины по
                 * тексту, так что измерению место только здесь. Начало — после '@': до
                 * него идентификатор, которому в журнале, уезжающем в трекер, не место. */
                const char *at = memchr(p, '@', len);
                const char *from = at ? at + 1 : p;
                size_t rest = (size_t)(e - from);
                struct vless_node t;
                memset(&t, 0, sizeof t);
                snprintf(t.name, sizeof t.name, "%zu байт: %s%.*s", len, at ? "…@" : "",
                         (int)(rest < 32 ? rest : 32), from);
                skip_note(st, &t, why);
            }
            /* ЧУЖОЙ ПРОТОКОЛ ЗДЕСЬ ТОЖЕ СЧИТАЕТСЯ. Короткую ссылку hy2/ss/trojan ветка ниже
             * учитывает в foreign — именно затем, чтобы расхождение «26 узлов в подписке, 17
             * у steer» объяснялось числом. Длиннее буфера такая ссылка не считалась нигде, и
             * арифметика (usable + skipped + foreign) не сходилась ровно на самом неожиданном
             * тексте подписки. Признак тот же, что у короткой («есть „://“»), только границу
             * даёт e, а не терминатор: строка здесь не копировалась в буфер. */
            else if (st) {
                for (const char *q = p; q + 3 <= e; q++)
                    if (!strncmp(q, "://", 3)) { st->foreign++; break; }
            }
        } else {
            memcpy(line, p, len);
            line[len] = '\0';
            /* Причина одна на все склейки — это один класс поломки подписки, и
             * группировать его по узлам незачем; всё, что различает случаи, уходит в
             * пример. Разбирать такую ссылку не пробуем вовсе: имя узла у неё заведомо
             * чужое, а адрес — может быть, и «может быть» здесь хуже честного отказа. */
            const char *glue = strncmp(line, "vless://", 8)
                                   ? NULL : glued_tail(line, line + len);
            if (glue) {
                glue_note(st, glue, line + len);
            } else if (!strncmp(line, "vless://", 8)) {
                struct vless_node node;
                int rc = vless_parse_url(line, &node);
                /* rc == 0 — узел взят; иначе НЕ ВЗЯТ, и для счётчика это одно и то
                 * же — узел, которого человек в списке не увидит, — а для объяснения
                 * разное: у «транспорт не поддержан» (1) причина уже названа разбором,
                 * у «ссылку не разобрали» (-1) её приходится называть здесь, потому
                 * что разбор бросил ссылку раньше, чем добрался до пригодности.
                 * Раньше -1 не считался нигде, и ссылка исчезала бесследно —
                 * так пропадал, например, узел с IPv6-литералом в host: первое
                 * двоеточие оказывается внутри скобок, порт читается как 0, разбор
                 * возвращает -1. Заголовок этого файла обещает обратное: «в ней 26
                 * узлов, а steer видит 17» должно объясняться цифрой. */
                /* Мест больше нет — считаем как пропущенный, а не бросаем остаток текста
                 * непрочитанным: то же обещание, что у конфига Xray, — арифметика
                 * usable + skipped + foreign обязана сходиться с числом ссылок. */
                if (rc == 0 && n < max) out[n++] = node;
                else if (rc == 0) skip_note(st, &node, "узлов больше, чем помещается");
                else skip_note(st, &node, rc > 0 ? node.skip_reason
                                                 : "ссылка не разобрана");
            } else if (strstr(line, "://") && st) {
                /* hy2, ss, trojan и прочее. Считаем, но не трогаем: подписка общая, а
                 * «26 узлов в подписке, 17 у steer» должно объясняться числом. */
                st->foreign++;
            }
        }
        p = e;
    }
    return n;
}

/* Привести прочитанный файл подписки к тексту, который понимает vless_parse_sub.
 *
 * Три вида, и различаются они первым непробельным знаком, а не догадкой:
 *   '[' или '{'  — конфиг Xray в JSON, отдаётся как есть;
 *   есть «://»   — список ссылок, отдаётся как есть;
 *   иначе        — base64, раскодируется в dec.
 *
 * Раньше это решение жило в tunnel.c одной строкой `if (!strstr(raw, "://"))`, и на конфиге
 * Xray оно срабатывало ПО СЛУЧАЙНОСТИ: «://» там есть внутри настроек DNS. Здесь оно потому,
 * что здесь его можно проверить стендом — туннель требует и сети, и TUN, и TLS.
 *
 * Возвращает raw или dec; ни то, ни другое не освобождается — буферы вызывающего. */
const char *vless_sub_text(const char *raw, size_t raw_n, char *dec, size_t dec_n) {
    const char *p = raw;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '[' || *p == '{') return raw;
    if (looks_clash(p)) return raw;
    if (strstr(raw, "://")) return raw;
    b64_decode(raw, raw_n, dec, dec_n);
    return dec;
}

/* Подписка из файла целиком: буферы и массив узлов — в куче по размеру файла и числу узлов в нём.
 * Раньше буферы были статикой в 256 КиБ, а узлов — 128 (статика в 157 КБ): подписка длиннее
 * теряла хвост, узлов больше — «не помещаются». Мест под узлы столько, сколько в тексте ссылок
 * («://») и объектов Xray («"protocol"») — верхняя граница числа узлов; остаток арифметики
 * (usable + skipped + foreign) сходится, как и прежде. Потолок файла — 64 МиБ: защита от файла-
 * не-подписки под этим именем, а не размер подписки (тысяча узлов — сотни килобайт).
 * NULL — файл не открылся, слишком велик или нет памяти; иначе массив (free), *cnt — узлов. */
#define VLESS_SUB_FILE_MAX ((size_t)64 << 20)
struct vless_node *vless_load_sub(const char *path, size_t *cnt, struct vless_sub_stats *st) {
    *cnt = 0;
    if (st) memset(st, 0, sizeof(*st));
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long fl = ftell(f);
    rewind(f);
    if (fl < 0 || (size_t)fl > VLESS_SUB_FILE_MAX) { fclose(f); return NULL; }
    size_t sz = (size_t)fl;
    char *raw = malloc(sz + 1), *dec = malloc(sz + 16);
    if (!raw || !dec) { fclose(f); free(raw); free(dec); return NULL; }
    size_t n = fread(raw, 1, sz, f);
    fclose(f);
    raw[n] = '\0';
    dec[0] = '\0';
    const char *text = vless_sub_text(raw, n, dec, sz + 16);
    size_t hint = 1;
    for (const char *q = text; (q = strstr(q, "://")); q += 3) hint++;
    for (const char *q = text; (q = strstr(q, "\"protocol\"")); q += 10) hint++;
    struct vless_node *nodes = calloc(hint, sizeof(*nodes));
    if (nodes) *cnt = vless_parse_sub(text, nodes, hint, st);
    free(raw);
    free(dec);
    return nodes;
}
