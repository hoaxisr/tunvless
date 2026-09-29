/* Апстримы резолвера без сети: разбор адреса, спека v2 с dns, таблица «демон -> dnsd» (построение и
 * разбор, старый формат до байта), кэш ответов (срок, зажим, возраст, отрицательные, вытеснение).
 * Сеть, TLS и путь через выход проверяет tests/dnsup.sh. Устройство проверяемого — src/dnsd/dup.h. */
#include "dnsd_int.h"
#include "tabfmt.h"
#include <sys/stat.h>

static int fails;
static void check(const char *what, int want, int got) {
    int ok = want == got;
    if (!ok) fails++;
    printf("%-64s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) printf("   ожидалось %d, получено %d\n", want, got);
}
static void check_str(const char *what, const char *want, const char *got) {
    int ok = !strcmp(want, got);
    if (!ok) fails++;
    printf("%-64s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) printf("   ожидалось «%s», получено «%s»\n", want, got);
}

static int parse(const char *u, struct spec_dns_up *o) {
    char why[128];
    memset(o, 0, sizeof(*o));
    return dnsurl_parse(u, o, why, sizeof(why));
}

/* Ответ A: имя a.b, TTL ttl, адрес 1.2.3.4. */
static size_t mk_answer(uint8_t *b, const char *name_lbl, uint32_t ttl, int rcode, int with_rr) {
    size_t o = 0;
    memset(b, 0, 12);
    b[2] = 0x81; b[3] = (uint8_t)(0x80 | rcode); b[5] = 1; b[7] = with_rr ? 1 : 0;
    o = 12;
    for (const char *p = name_lbl; *p;) {
        const char *d = strchr(p, '.');
        size_t l = d ? (size_t)(d - p) : strlen(p);
        b[o++] = (uint8_t)l; memcpy(b + o, p, l); o += l;
        p += l + (d ? 1 : 0);
    }
    b[o++] = 0; b[o++] = 0; b[o++] = 1; b[o++] = 0; b[o++] = 1;
    if (with_rr) {
        b[o++] = 0xC0; b[o++] = 12; b[o++] = 0; b[o++] = 1; b[o++] = 0; b[o++] = 1;
        b[o++] = (uint8_t)(ttl >> 24); b[o++] = (uint8_t)(ttl >> 16); b[o++] = (uint8_t)(ttl >> 8); b[o++] = (uint8_t)ttl;
        b[o++] = 0; b[o++] = 4; b[o++] = 1; b[o++] = 2; b[o++] = 3; b[o++] = 4;
    }
    return o;
}
static size_t mk_query(uint8_t *b, const char *name) {
    size_t n = mk_answer(b, name, 0, 0, 0);
    b[2] = 0x01; b[3] = 0;
    return n;
}
static uint32_t rr_ttl(const uint8_t *a, size_t n, size_t qlen) {
    (void)n;
    return ((uint32_t)a[qlen + 6] << 24) | ((uint32_t)a[qlen + 7] << 16) | ((uint32_t)a[qlen + 8] << 8) | a[qlen + 9];
}

int main(void) {
    struct spec_dns_up u;
    /* ---- адрес апстрима ---- */
    check("https://dns.google/dns-query — DoH", 0, parse("https://dns.google/dns-query", &u));
    check("  протокол", DNSP_DOH, u.proto);
    check("  порт 443", 443, u.port);
    check_str("  путь", "/dns-query", u.path);
    check("https://h:8443/x — порт и путь", 0, parse("https://h.test:8443/x", &u));
    check("  порт", 8443, u.port);
    check_str("  путь", "/x", u.path);
    check("https://h без пути — путь по умолчанию", 0, parse("https://h.test", &u));
    check_str("  путь", "/dns-query", u.path);
    check("tls://one.one.one.one — DoT 853", 0, parse("tls://one.one.one.one", &u));
    check("  порт", 853, u.port);
    check("tls://[2606:4700::1111]:853 — IPv6 в скобках", 0, parse("tls://[2606:4700::1111]", &u));
    check_str("  адрес", "2606:4700::1111", u.host);
    check("udp://1.1.1.1 — порт 53", 0, parse("udp://1.1.1.1", &u));
    check("  порт", 53, u.port);
    check("udp://имя — отказ (обычному DNS нечем разрешить имя)", -1, parse("udp://dns.test", &u));
    check("quic:// — пока отказ", -1, parse("quic://dns.test", &u));
    check("http:// — отказ", -1, parse("http://dns.test", &u));
    check("путь у tls:// — отказ", -1, parse("tls://dns.test/x", &u));
    check("порт 99999 — отказ", -1, parse("tls://dns.test:99999", &u));

    /* ---- спека v2 ---- */
    char dir[] = "/tmp/dupmatchXXXXXX";
    if (!mkdtemp(dir)) return 2;
    char lst[200], sp[200];
    snprintf(lst, sizeof(lst), "%s/a.lst", dir);
    snprintf(sp, sizeof(sp), "%s/s.yaml", dir);
    FILE *f = fopen(lst, "w"); fputs("a.test\n", f); fclose(f);
    char lst2[200]; snprintf(lst2, sizeof(lst2), "%s/b.lst", dir);
    f = fopen(lst2, "w"); fputs("b.test\n", f); fclose(f);
    f = fopen(sp, "w");
    fprintf(f, "version: 2\nlan: { devices: [br-lan] }\nlists:\n  la: { domains_file: %s }\n  lb: { domains_file: %s }\n"
               "outputs:\n  direct: { kind: direct }\n  vpn: { kind: interface, device: wg0 }\n"
               "dns:\n  cache: 128\n  cache_ttl: { min: 20, max: 900, negative: 45 }\n  bootstrap: [1.1.1.1, 8.8.8.8]\n"
               "  upstream: g\n  upstreams:\n    g: { url: 'https://dns.google/dns-query', out: vpn }\n"
               "    t: { url: 'tls://dns.test', ips: [192.0.2.1] }\n"
               "rules:\n  - { name: ra, to: [la], out: vpn, dns: t }\n  - { name: rb, to: [lb], out: vpn }\n", lst, lst2);
    fclose(f);
    static struct spec cfg;
    struct err e = {0};
    check("спека с dns.upstreams/bootstrap/cache читается", 0, load_spec(sp, &cfg, &e) < 0);
    check("  кэш", 128, (int)cfg.dns.cache);
    check("  ttl min/max/neg", 20 * 1000000 + 900 * 1000 + 45, (int)(cfg.dns.ttl_min * 1000000 + cfg.dns.ttl_max * 1000 + cfg.dns.ttl_neg));
    check("  общий апстрим — первый", 1, cfg.dns.general);
    check("  bootstrap из двух", 2, cfg.dns.boot_n);
    check("  апстрим t: адреса записаны", 1, cfg.dns.up[1].ips_n);

    /* ---- таблица: построение и разбор ---- */
    cfg.out[1].mark = 0x00100000;     /* метку выдал бы реестр демона */
    char *txt = NULL; size_t tn = 0;
    FILE *m = open_memstream(&txt, &tn);
    tabfmt_build(&cfg, m); fclose(m);
    check("таблица: расширенный заголовок «2 2 128 20 900 45»", 0, strncmp(txt, "2 2 128 20 900 45\n", 18));
    check("  канал ra несёт dns:1, rb — dns:2 (порядок использования)", 1,
          strstr(txt, "|dns:1\n") != NULL && strstr(txt, "|dns:2\n") != NULL);
    check("  метка выхода в строке апстрима g", 1, strstr(txt, "https://dns.google/dns-query|vpn|1048576|-|1.1.1.1,8.8.8.8") != NULL);
    check("  для t (без выхода): метка 0, адреса", 1, strstr(txt, "tls://dns.test|-|0|192.0.2.1|1.1.1.1,8.8.8.8") != NULL);
    size_t before_n = g_dup_cfg_n;
    check("  разбор своей же таблицы", 0, tabfmt_parse(txt, tn));
    check("  апстримов", (int)before_n, (int)g_dup_cfg_n);
    check("  протокол t — DoT", DNSP_DOT, g_dup_cfg[0].u.proto == DNSP_DOT ? DNSP_DOT : g_dup_cfg[1].u.proto);
    check("  кэш из заголовка", 128, (int)g_dcache_cfg.entries);
    check("  у канала апстрим", 1, g_dch[0].up > 0 && g_dch[1].up > 0);
    free(txt);

    /* Без dns — старый формат до байта. */
    f = fopen(sp, "w");
    fprintf(f, "version: 2\nlan: { devices: [br-lan] }\nlists:\n  la: { domains_file: %s }\n"
               "outputs:\n  vpn: { kind: interface, device: wg0 }\nrules:\n  - { name: ra, to: [la], out: vpn }\n", lst);
    fclose(f);
    static struct spec cfg2;
    check("спека без dns читается", 0, load_spec(sp, &cfg2, &e) < 0);
    txt = NULL; m = open_memstream(&txt, &tn);
    tabfmt_build(&cfg2, m); fclose(m);
    check("таблица без dns: заголовок «1»", 0, strncmp(txt, "1\n", 2));
    check("  ни одного dns: и строки апстрима", 1, strstr(txt, "dns:") == NULL && g_dup_cfg_n == 0);
    check("  разбор старой", 0, tabfmt_parse(txt, tn));
    check("  кэша нет", 0, (int)g_dcache_cfg.entries);
    free(txt);

    /* Отказы спеки. */
    const char *bad[] = {
        "dns: { upstreams: { a: { url: 'tls://dns.test' } } }",                    /* нечем разрешить имя */
        "dns: { upstreams: { a: { url: 'quic://dns.test', ips: [1.1.1.1] } } }",     /* DoQ */
        "dns: { upstream: nope }",                                                  /* нет такого */
        "dns: { upstreams: { a: { url: 'tls://1.1.1.1', out: nope } } }",          /* нет выхода */
        "dns: { cache_ttl: { min: 100, max: 10 } }",                                /* min > max */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        f = fopen(sp, "w");
        fprintf(f, "version: 2\nlan: { devices: [br-lan] }\noutputs:\n  vpn: { kind: interface, device: wg0 }\n%s\n", bad[i]);
        fclose(f);
        static struct spec cfg3;
        memset(&cfg3, 0, sizeof(cfg3));
        struct err e3 = {0};
        char nm[80]; snprintf(nm, sizeof(nm), "отказ спеки №%zu", i + 1);
        check(nm, 1, load_spec(sp, &cfg3, &e3) < 0);
    }

    /* ---- кэш ---- */
    struct dcache_cfg cc = { 8, 10, 100, 30 };
    dcache_config(&cc);
    uint8_t a[512], q[512], out[512];
    size_t an = mk_answer(a, "x.test", 300, 0, 1), qn = mk_query(q, "x.test");
    size_t qlen = an - 16;
    check("кэш включён", 1, dcache_on());
    check("положен ответ", 1, dcache_put(1, a, an, 1000));
    size_t on = dcache_get(1, q, qn, out, sizeof(out), 1010);
    check("выдан из кэша", (int)an, (int)on);
    check("  номер — как у вопроса", (q[0] << 8) | q[1], (out[0] << 8) | out[1]);
    check("  TTL зажат сверху (300 -> 100) и уменьшен на возраст 10", 90, (int)rr_ttl(out, on, qlen));
    check("  другой апстрим — промах", 0, (int)dcache_get(2, q, qn, out, sizeof(out), 1010));
    check("  после срока — промах", 0, (int)dcache_get(1, q, qn, out, sizeof(out), 1100));
    an = mk_answer(a, "y.test", 2, 0, 1);
    dcache_put(1, a, an, 2000);
    qn = mk_query(q, "y.test");
    on = dcache_get(1, q, qn, out, sizeof(out), 2000);
    check("TTL 2 поднят до min 10", 10, (int)rr_ttl(out, on, an - 16));
    an = mk_answer(a, "n.test", 0, 3, 0);
    check("NXDOMAIN кладётся", 1, dcache_put(1, a, an, 3000));
    qn = mk_query(q, "n.test");
    check("  живёт negative (30 с)", 1, dcache_get(1, q, qn, out, sizeof(out), 3029) > 0);
    check("  и не дольше", 0, (int)dcache_get(1, q, qn, out, sizeof(out), 3030));
    an = mk_answer(a, "s.test", 0, 2, 0);
    check("SERVFAIL не кладётся", 0, dcache_put(1, a, an, 3000));
    an = mk_answer(a, "Z.Test", 60, 0, 1);
    dcache_put(1, a, an, 4000);
    qn = mk_query(q, "z.TEST");
    check("имя без учёта регистра", 1, dcache_get(1, q, qn, out, sizeof(out), 4001) > 0);
    for (int i = 0; i < 40; i++) {
        char nm[32]; snprintf(nm, sizeof(nm), "e%d.test", i);
        an = mk_answer(a, nm, 60, 0, 1);
        dcache_put(1, a, an, 5000);
    }
    struct dcache_cfg c0 = { 0, 0, 0, 0 };
    dcache_config(&c0);
    check("кэш 0 — выключен", 0, dcache_on());

    unlink(lst); unlink(lst2); unlink(sp); rmdir(dir);
    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
