#include "dnsd_int.h"
#include "nftnl.h"
#include "srs.h"

/* ---------------------------------------------------------------------- */
/* fake-IP pool: one stable, exclusive synthetic IPv4 per matched domain    */
/* ---------------------------------------------------------------------- */
/* Real CDN-fronted IPs (Cloudflare etc.) are shared across many unrelated
 * customer domains from a dynamic anycast pool — there is no fixed 1:1
 * domain->IP mapping, so tagging the real resolved IP into a set (as
 * nft_add_element above does) is collision-prone: two configured domains
 * can end up sharing one real IP, and then whichever one's set entry is
 * freshest decides routing for BOTH. Handing the client a synthetic IP that
 * THIS daemon allocates and owns 1:1 per domain makes that collision
 * structurally impossible, and — since the decision is made from the DNS
 * question name, always visible in plaintext — sidesteps ECH entirely (no
 * TLS/SNI parsing needed at all). Pool: 198.18.0.0/15, the RFC 2544
 * benchmarking range, the same convention already used by Clash/sing-box/
 * mihomo for this exact purpose; effectively never a real destination. */
/* FAKEIP_POOL_BASE/SIZE — в dnsd_int.h. */

/* ПУЛ fake-IP v6 (docs/architecture.md, «4б»): fdfe:dcba:9876::/96, и адрес — это поддельный IPv4
 * той же записи в младших 32 битах (fakeip6_of, spec.h): у youtube.com с 198.18.0.5 поддельный
 * IPv6 — fdfe:dcba:9876::c612:5.
 *
 * ПОЧЕМУ ТАКОЙ ПРЕФИКС. Уникальный локальный адрес (fc00::/7, RFC 4193) в интернете не
 * маршрутизируется, то есть настоящим назначением не бывает никогда — то же свойство, ради
 * которого у IPv4 взят 198.18.0.0/15. Сам префикс — тот же, что у mihomo (fake-ip-range6), по той
 * же причине, по которой пул IPv4 совпадает с Clash и sing-box: это соглашение, и с настоящей
 * сетью оно не столкнётся — локальный префикс роутера (ula_prefix OpenWrt) выбирается случайно из
 * 2^40 вариантов. Половина fd00::/8, а не fc00::/8, как у sing-box: fc00::/8 зарезервирована под
 * централизованную раздачу, и что с ней сделает завтрашний стек, не знает никто.
 *
 * ПОЧЕМУ ПАРА К IPv4, А НЕ СВОЯ ВЫДАЧА. Запись домена одна, и адресов у неё два: выдавать их
 * отдельно — значит держать второй счётчик, вторую верхнюю отметку, второе поле «пул исчерпан» и
 * следить, чтобы у домена не оказалось IPv6 от одной записи и IPv4 от другой. Пара выводится из
 * адреса IPv4, поэтому хранить её не надо вовсе (в файле состояния — только настоящий IPv6), по
 * ней explain сразу называет домен, а адреса сети и последнего у неё нет по той же причине, что у
 * IPv4 (выдача начинается с 1 и не доходит до последнего). /96 — место под все 2^32 адресов, хотя
 * заняты из них только 2^17 пула IPv4. */
const char *g_fakeip6_map = "fakeip6";

struct fakeip_table g_fakeip;
const char *g_fakeip_state_path;

/* Индекс домен -> номер записи. Тот же приём, что у правил, и по той же причине: без него
 * каждый ответ стоил трёх переборов таблицы со сравнением строк, а загрузка состояния была
 * квадратичной — файл на 5000 записей означал 12,5 миллиона сравнений при старте. */
struct sindex g_fakeip_idx;

static const char *fakeip_key(const void *owner, uint32_t idx) {
    return ((const struct fakeip_table *)owner)->entries[idx].domain;
}

/* Номер записи домена или -1. Единственное место поиска: три прежних копии этого перебора
 * (найти, прочитать реальный адрес, записать его) разошлись бы при первом же изменении. */
long fakeip_find(const char *domain) {
    uint32_t hit = sindex_get(&g_fakeip_idx, &g_fakeip, fakeip_key, domain);
    return hit ? (long)((hit & SIDX_IDX_MASK) - 1) : -1;
}

static uint32_t fakeip_index_to_addr(size_t idx) { return FAKEIP_POOL_BASE + (uint32_t)idx; }

/* Next pool index to hand out — a HIGH-WATER MARK, not the entry count.
 *
 * Deriving the index from t->n only works while the file is a dense 0..n-1
 * prefix, and it is not: the --fakeip CLI appends an entry it just looked up, so
 * a duplicate line is normal, and a skipped (malformed) line leaves a hole. With
 * a count-based index, `a -> .3` alone in the file makes the fourth new domain
 * allocate .3 as well — two domains on ONE fake IP, whose DNAT entry then points
 * at whichever was inserted last, i.e. one of them silently reaches the other's
 * site.
 *
 * Starts at 1, not 0: index 0 is 198.18.0.0 — the network address of the pool, which some
 * stacks and tools treat as unusable (found on Cuttlefish, Android 16). The last index is
 * skipped for the same reason (see the exhaustion check in fakeip_lookup_or_alloc). An old
 * state file that already maps a domain to .0 is loaded as is — no migration. */
size_t g_fakeip_next = 1;

static int fakeip_table_add(struct fakeip_table *t, const char *domain, uint32_t addr) {
    if (t->n == t->cap) {
        size_t newcap = t->cap ? t->cap * 2 : 64;
        struct fakeip_entry *ne = realloc(t->entries, newcap * sizeof(*ne));
        if (!ne) return -1;
        t->entries = ne;
        t->cap = newcap;
    }
    t->entries[t->n].domain = strdup(domain);
    if (!t->entries[t->n].domain) return -1;
    t->entries[t->n].addr = addr;
    t->entries[t->n].real_host = 0;
    t->entries[t->n].sets = 0;            /* unknown until the resolver routes it */
    t->entries[t->n].route_asserted = 0;
    t->entries[t->n].refreshed = 0;
    memset(t->entries[t->n].real6, 0, 16);
    t->entries[t->n].has_real6 = 0;
    t->entries[t->n].sets6 = 0;
    t->entries[t->n].route6_asserted = 0;
    t->entries[t->n].refreshed6 = 0;
    t->n++;
    if (t == &g_fakeip &&
        sindex_put(&g_fakeip_idx, t, fakeip_key, t->entries[t->n - 1].domain,
                   (uint32_t)(t->n - 1), 0) != 0) {
        /* Индекс не вырос — запись всё равно добавлена, но найти её будет нечем. Честнее
         * откатить, чем оставить домен, который существует и не находится: иначе он получит
         * второй адрес при следующем запросе, а DNAT будет показывать на один из них. */
        free(t->entries[t->n - 1].domain);
        t->n--;
        return -1;
    }
    if (addr >= FAKEIP_POOL_BASE && addr < FAKEIP_POOL_BASE + FAKEIP_POOL_SIZE) {
        size_t idx = (size_t)(addr - FAKEIP_POOL_BASE);
        if (idx + 1 > g_fakeip_next) g_fakeip_next = idx + 1;
    }
    return 0;
}

/* 0 iff DOMAIN already has an allocation. */
static int fakeip_table_has(const struct fakeip_table *t, const char *domain) {
    (void)t;
    return fakeip_find(domain) >= 0 ? 0 : -1;
}

/* State file format: one entry per line.
 *   domain\tfake_ip            (legacy / --fakeip CLI output)
 *   domain\tfake_ip\treal_ip   (extended: real backend, for post-restart rehydrate)
 *   domain\tfake_ip\treal_ip\treal_ip6
 *   domain\tfake_ip\t-\treal_ip6
 *                              (1.9, fake-IP v6: настоящий IPv6 под элементом карты fakeip6;
 *                               «-» — настоящий IPv4 не известен. Поддельный IPv6 не пишется —
 *                               он выводится из fake_ip, см. шапку файла)
 * Missing file -> empty table, not an error (first run). A malformed line is
 * skipped, not fatal — the domain simply gets re-allocated (a fresh index) on
 * the next match. The legacy 2-field form is parsed identically to before, so
 * an existing state file upgrades transparently. Испорченное четвёртое поле строку не
 * отвергает: пропадает только настоящий IPv6, и первый AAAA спросит его заново. */
void fakeip_state_load(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[MAX_HOSTNAME + 128];          /* имя, два адреса IPv4, IPv6 и табуляции */
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
        char *tab1 = strchr(line, '\t');
        if (!tab1) continue;
        *tab1 = '\0';
        /* Terminate the fake-IP field BEFORE parsing it. inet_aton() rejects a
         * string with anything after the address, so reading the 3-field form
         * without cutting at the second tab fed it "198.18.0.0\t104.20.39.144"
         * and skipped the line — and since the daemon REWRITES the file in the
         * 3-field form as soon as a domain's real backend is known, that made
         * every restart lose the whole table. Consequences, in order of how much
         * they hurt: fake IPs are handed out again from the start of the pool, so
         * an address a client still has cached now DNATs to a DIFFERENT site's
         * backend; the rehydrate pass below never had anything to rehydrate; and
         * the first query per domain after a restart relays the real answer. */
        char *fake_s = tab1 + 1;
        char *tab2 = strchr(fake_s, '\t');
        if (tab2) *tab2 = '\0';
        struct in_addr a;
        if (inet_aton(fake_s, &a) == 0) continue;
        /* Адрес вне пула — брак строки, а не запись: одна такая строка (203.0.113.5) ставила
         * верхнюю отметку пула за его край, и каждый новый домен получал «пул исчерпан»
         * навсегда, а сам чужой адрес выдавался клиентам как поддельный. */
        if (ntohl(a.s_addr) < FAKEIP_POOL_BASE ||
            ntohl(a.s_addr) >= FAKEIP_POOL_BASE + FAKEIP_POOL_SIZE) continue;
        /* Keep the FIRST allocation for a domain: a duplicate line is expected
         * (the --fakeip CLI appends what it looked up), and adding it twice would
         * both bloat the table and, before the high-water mark above, corrupt the
         * next index. */
        if (fakeip_table_has(&g_fakeip, line) == 0) continue;
        if (fakeip_table_add(&g_fakeip, line, ntohl(a.s_addr)) != 0) continue;

        if (tab2) { /* optional third field: last-seen real backend */
            char *real_s = tab2 + 1;
            char *tab3 = strchr(real_s, '\t');
            if (tab3) *tab3 = '\0';
            struct in_addr r;
            if (inet_aton(real_s, &r) != 0)
                g_fakeip.entries[g_fakeip.n - 1].real_host = ntohl(r.s_addr);
            uint8_t r6[16];
            if (tab3 && inet_pton(AF_INET6, tab3 + 1, r6) == 1) {
                memcpy(g_fakeip.entries[g_fakeip.n - 1].real6, r6, 16);
                g_fakeip.entries[g_fakeip.n - 1].has_real6 = 1;
            }
        }
    }
    fclose(f);
}

static void fakeip_state_append(const char *path, const char *domain, uint32_t addr) {
    FILE *f = fopen(path, "a");
    if (!f) return;
    struct in_addr a; a.s_addr = htonl(addr);
    char ipstr[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr)))
        fprintf(f, "%s\t%s\n", domain, ipstr);
    fclose(f);
}

/* Rewrites the whole state file from g_fakeip in the extended 3-field format.
 * Called after we learn a fresh real_ip for an already-allocated domain, so
 * the next restart can rehydrate the DNAT map without re-resolving. Best-effort
 * (atomic via rename); a failure just means a later restart re-resolves. */
void fakeip_state_rewrite(void) {
    if (!g_fakeip_state_path) return;
    /* Буфер — по длине ПУТИ, а не имени хоста: путь состояния задаёт снаружи
     * (--state-file/--state-dir), и обрезка «%s.tmp» на произвольном месте давала
     * чужое имя — от несуществующего до самого файла состояния или существующего
     * каталога. Обрезка проверяется явно: писать некуда лучше, чем писать не туда. */
    char tmp[PATH_MAX];
    int need = snprintf(tmp, sizeof(tmp), "%s.tmp", g_fakeip_state_path);
    if (need < 0 || (size_t)need >= sizeof(tmp)) return;
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    for (size_t i = 0; i < g_fakeip.n; i++) {
        const struct fakeip_entry *en = &g_fakeip.entries[i];
        struct in_addr fa; fa.s_addr = htonl(en->addr);
        char fstr[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &fa, fstr, sizeof(fstr))) continue;
        char rstr[INET_ADDRSTRLEN] = "";
        if (en->real_host) {
            struct in_addr ra; ra.s_addr = htonl(en->real_host);
            if (!inet_ntop(AF_INET, &ra, rstr, sizeof(rstr))) rstr[0] = '\0';
        }
        char r6str[INET6_ADDRSTRLEN] = "";
        if (en->has_real6 && !inet_ntop(AF_INET6, en->real6, r6str, sizeof(r6str)))
            r6str[0] = '\0';
        /* Строка без IPv6 — прежней формы до байта: файл, который пишет движок без IPv6 в
         * доменных правилах, не меняется. */
        if (r6str[0])
            fprintf(f, "%s\t%s\t%s\t%s\n", en->domain, fstr, rstr[0] ? rstr : "-", r6str);
        else if (rstr[0])
            fprintf(f, "%s\t%s\t%s\n", en->domain, fstr, rstr);
        else
            fprintf(f, "%s\t%s\n", en->domain, fstr);
    }
    /* Данные должны лечь на носитель ДО rename: иначе отключение питания между
     * rename и фактической записью оставляет пустой state-файл — ровно ту
     * потерю всей таблицы, от которой защищается разбор в fakeip_state_load. */
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f);
        unlink(tmp);
        return;
    }
    fclose(f);
    if (rename(tmp, g_fakeip_state_path) != 0)
        unlink(tmp);
}

/* Looks up domain's existing fake IP, or allocates the next free one and
 * persists it. Returns 0 and fills *out_addr (host order) on success; -1 if
 * the pool is exhausted (caller falls back to relaying the real answer
 * unchanged — fail open, never block DNS over an exhausted pool). */
int fakeip_lookup_or_alloc(const char *domain_in, uint32_t *out_addr) {
    /* Ключ таблицы — строчные буквы, и приводит к ним сама таблица, а не каждый вызывающий:
     * демон приводил, команда `--fakeip` нет, и X.TEST получала второй адрес рядом с x.test. */
    char domain[MAX_HOSTNAME];
    snprintf(domain, sizeof(domain), "%s", domain_in);
    str_lower(domain);
    long at = fakeip_find(domain);
    if (at >= 0) {
        *out_addr = g_fakeip.entries[at].addr;
        return 0;
    }
    if (g_fakeip_next >= FAKEIP_POOL_SIZE - 1) {   /* последний — широковещательный пула */
        /* Пул кончился: домен уйдёт клиенту реальным адресом, то есть МИМО канала, в
         * который его положил человек. Молчать об этом нельзя — снаружи это «правило
         * перестало работать», и связать это с пулом нечем. */
        static time_t said_pool;
        time_t now = time(NULL);
        if (warn_due(&said_pool, now))
            fprintf(stderr, "steer dnsd: пул fake-IP исчерпан (%u адресов, занято %zu): "
                            "новые домены идут мимо каналов\n",
                    (unsigned)FAKEIP_POOL_SIZE, g_fakeip.n);
        return -1;
    }
    uint32_t addr = fakeip_index_to_addr(g_fakeip_next);
    if (fakeip_table_add(&g_fakeip, domain, addr) != 0) return -1;
    if (g_fakeip_state_path) fakeip_state_append(g_fakeip_state_path, domain, addr);
    *out_addr = addr;
    return 0;
}

int g_fakeip_dirty = 0;
time_t g_fakeip_last_rewrite = 0;

/* Records the last-seen real backend for an allocated domain. Called after a
 * successful DNAT-map insert so the mapping can survive a restart via the
 * rehydrate pass (run_proxy's startup). Triggers a one-shot state rewrite so
 * the extended 3-field form persists. */
/* The real backend we last installed for this domain, or 0 if we never did. */
uint32_t fakeip_entry_get_real(const char *domain) {
    long at = fakeip_find(domain);
    return at >= 0 ? g_fakeip.entries[at].real_host : 0;
}

void fakeip_entry_set_real(const char *domain, uint32_t real_host) {
    long at = fakeip_find(domain);
    if (at < 0) return;
    if (g_fakeip.entries[at].real_host == real_host) return;
    g_fakeip.entries[at].real_host = real_host;
    g_fakeip_dirty = 1;
}

/* Половина IPv6: то же для карты fakeip6 — только после ack ядра (как real_host). */
const uint8_t *fakeip_entry_get_real6(const char *domain) {
    long at = fakeip_find(domain);
    return at >= 0 && g_fakeip.entries[at].has_real6 ? g_fakeip.entries[at].real6 : NULL;
}

void fakeip_entry_set_real6(const char *domain, const uint8_t real6[16]) {
    long at = fakeip_find(domain);
    if (at < 0) return;
    struct fakeip_entry *e = &g_fakeip.entries[at];
    if (e->has_real6 && !memcmp(e->real6, real6, 16)) return;
    memcpy(e->real6, real6, 16);
    e->has_real6 = 1;
    g_fakeip_dirty = 1;
}

/* Ensures DOMAIN's fake IP is a PERMANENT member of channel NEW_SET_IDX's nft set
 * (g_dch[new_set_idx].set), moving it from its previous channel set if the domain
 * has been re-classified. Defined after g_dch (below): it needs the channel table.
 *
 * Why this is NOT a timeout element (and why it has to live here, beside the real
 * backend bookkeeping): a fake IP is a STABLE, exclusive allocation — it never
 * moves in the pool, and the DNAT map holds it forever. The channel set is the
 * routing decision (`ip daddr @set -> meta mark set`), and it used to inherit the
 * real answer's TTL. That TTL (often 30-60s for a CDN) is far shorter than the
 * long-lived TCP/QUIC sessions clients open against the resolved domain. When the
 * element expired, the mark rule stopped matching, the packet fell through to the
 * default route — the WAN — and the session to the VPN-hosted site broke for a
 * second. Reproduced on the router: conntrack showed claude.ai flows with
 * mark=0 leaving via the WAN address while the tunnel itself stayed perfectly
 * healthy. A permanent element makes the route match the lifetime of the
 * allocation, which is what a routing decision should do.
 *
 * Channel reassignment: if the ruleset is edited so a domain now matches a
 * different channel, the fake IP must move to that channel's set — leaving it in
 * the old one would keep steering it the old way. Best-effort on the delete: a
 * missing element is exactly the post-restart state and is harmless. */
const char *g_fakeip_map = "fakeip";

/* ---- адрес имени в наборе канала -------------------------------------------------------------
 *
 * Обычный набор — адрес. Составной (канал со смешанным сужением, src/model/srsplan.c) — адрес
 * . протокол . порты: имя попадает туда с сужением тех правил канала, с которыми совпало, а
 * если совпало с несколькими — их объединением, разложенным на непересекающиеся ящики (ядро не
 * принимает в составной набор пересекающиеся элементы). */
static size_t dch_boxes(size_t i, const char *domain, struct nftlk_box *out) {
    static const struct l4match none;
    const struct dchan *d = &g_dch[i];
    const struct l4match *ms[64];
    size_t k = 0;
    if (ruleset_match(&d->rules, domain)) ms[k++] = &none;
    for (size_t p = 0; p < d->parts_n && k < 64; p++)
        if (ruleset_match(&d->parts[p].rules, domain) &&
            !(d->parts[p].has_excl && ruleset_match(&d->parts[p].excl, domain)))
            ms[k++] = &d->parts[p].l4;
    /* Правила сменились с тех пор, как адрес туда лёг (удаление после перечитывания): прежнего
     * сужения уже не узнать — берётся полный ящик, лучшее, что можно сделать. */
    if (!k) ms[k++] = &none;
    struct l4box b[L4BOX_MAX];
    size_t n = l4_union_boxes(ms, k, b);
    for (size_t j = 0; j < n; j++) {
        out[j].plo = b[j].plo;
        out[j].phi = b[j].phi;
        out[j].lo = b[j].lo;
        out[j].hi = b[j].hi;
    }
    return n;
}

int dch_add(size_t i, const char *domain, uint32_t addr_host, uint32_t ttl) {
    if (!g_dch[i].composite) return nft_add_element(g_dch[i].set, addr_host, ttl);
    struct nftlk_box b[L4BOX_MAX];
    size_t n = dch_boxes(i, domain, b);
    int rc = 0;
    for (size_t j = 0; j < n; j++)
        if (nft_concat_element(1, g_dch[i].set, addr_host, &b[j], ttl) != 0) rc = -1;
    return rc;
}

void dch_del(size_t i, const char *domain, uint32_t addr_host) {
    if (!g_dch[i].composite) {
        uint32_t k_net = htonl(addr_host);
        int drc = nftlk_elem_msg(NFT_MSG_DELSETELEM, g_nft_table, g_dch[i].set,
                                 &k_net, g_nft_sets_interval, NULL, 0);
        if (drc != 0 && drc != -ENOENT && dbg())
            fprintf(stderr, "nftlk: channel-move delete from %s rc=%d\n", g_dch[i].set, drc);
        return;
    }
    struct nftlk_box b[L4BOX_MAX];
    size_t n = dch_boxes(i, domain, b);
    for (size_t j = 0; j < n; j++) nft_concat_element(0, g_dch[i].set, addr_host, &b[j], 0);
}

/* Адрес IPv6 — в парный набор «<set>6» (компилятор заводит его доменной группе с dom6, тем же
 * именем, что group_set6_name). Сужение составного набора — то же, что у IPv4 (dch_boxes). */
static void dch_set6_name(size_t i, char *dst, size_t n) {
    snprintf(dst, n, "%.62s6", g_dch[i].set);
}

int dch_add6(size_t i, const char *domain, const uint8_t addr[16], uint32_t ttl) {
    char s6[80];
    dch_set6_name(i, s6, sizeof(s6));
    if (!g_dch[i].composite) return nft_add_element6(s6, addr, ttl);
    struct nftlk_box b[L4BOX_MAX];
    size_t n = dch_boxes(i, domain, b);
    int rc = 0;
    for (size_t j = 0; j < n; j++)
        if (nft_concat_element6(1, s6, addr, &b[j], ttl) != 0) rc = -1;
    return rc;
}

void dch_del6(size_t i, const char *domain, const uint8_t addr[16]) {
    char s6[80];
    dch_set6_name(i, s6, sizeof(s6));
    if (!g_dch[i].composite) {
        int drc = nftlk_elem_msg6(NFT_MSG_DELSETELEM, g_nft_table, s6, addr,
                                  g_nft_sets_interval, NULL, 0);
        if (drc != 0 && drc != -ENOENT && dbg())
            fprintf(stderr, "nftlk: channel-move delete from %s rc=%d\n", s6, drc);
        return;
    }
    struct nftlk_box b[L4BOX_MAX];
    size_t n = dch_boxes(i, domain, b);
    for (size_t j = 0; j < n; j++) nft_concat_element6(0, s6, addr, &b[j], 0);
}

void fakeip_route_set(const char *domain, uint64_t want) {
    long at = fakeip_find(domain);
    if (at < 0) return;
    if (g_dch_n < 64) want &= (1ULL << g_dch_n) - 1ULL;
    if (!want) return;

    uint64_t old = g_fakeip.entries[at].sets;
    if (old == want) {
        /* Те же наборы: постоянные элементы уже стоят (или пережили прошлый запуск).
         * Переутверждаем идемпотентно — ядро, потерявшее их (fw4 reload смывает
         * наборы), получает их обратно, не дожидаясь повторного разрешения имени.
         *
         * Но не чаще TTL ответа: без дросселя КАЖДЫЙ повторный запрос платил
         * блокирующей nf_tables-транзакцией за ответ EEXIST — и второй раз тем
         * же, когда фоновый ответ upstream доходил до этой же строки. После
         * fw4 reload элемент вернётся с первым запросом по истечении TTL —
         * раньше клиент со старым кешем и не придёт. */
        time_t now = time(NULL);
        if (now - g_fakeip.entries[at].route_asserted < FAKEIP_ANSWER_TTL)
            return;
        g_fakeip.entries[at].route_asserted = now;
        for (size_t i = 0; i < g_dch_n; i++)
            if (want & (1ULL << i))
                dch_add(i, domain, g_fakeip.entries[at].addr, 0);
        return;
    }

    /* Убираем из наборов, которым имя больше не принадлежит: правило выключили,
     * удалили или переписали его списки. ENOENT законен — удалять нечего
     * (перезапуск, или элемент туда и не лёг). */
    for (size_t i = 0; i < g_dch_n; i++) {
        if (!(old & (1ULL << i)) || (want & (1ULL << i))) continue;
        dch_del(i, domain, g_fakeip.entries[at].addr);
    }

    /* И кладём во все, где его ещё нет, постоянным элементом. EEXIST — уже
     * желаемое состояние. */
    for (size_t i = 0; i < g_dch_n; i++)
        if ((want & (1ULL << i)) && !(old & (1ULL << i)))
            dch_add(i, domain, g_fakeip.entries[at].addr, 0);
    g_fakeip.entries[at].sets = want;
    g_fakeip.entries[at].route_asserted = time(NULL);
}

/* То же для поддельного IPv6 — постоянный элемент в «<канал>6» каждого канала из want, с тем же
 * дросселем переутверждения и тем же переездом между каналами. want — только каналы с DCH_V6:
 * у остальных набора IPv6 нет (и AAAA им адресом не отвечают — dch_all_v6). */
void fakeip_route_set6(const char *domain, uint64_t want) {
    long at = fakeip_find(domain);
    if (at < 0) return;
    if (g_dch_n < 64) want &= (1ULL << g_dch_n) - 1ULL;
    for (size_t i = 0; i < g_dch_n && i < 64; i++)
        if (!(g_dch[i].fam & DCH_V6)) want &= ~(1ULL << i);
    if (!want) return;
    struct fakeip_entry *e = &g_fakeip.entries[at];
    uint8_t f6[16];
    fakeip6_of(e->addr, f6);
    uint64_t old = e->sets6;
    time_t now = time(NULL);
    if (old == want) {
        if (now - e->route6_asserted < FAKEIP_ANSWER_TTL) return;
        e->route6_asserted = now;
        for (size_t i = 0; i < g_dch_n; i++)
            if (want & (1ULL << i)) dch_add6(i, domain, f6, 0);
        return;
    }
    for (size_t i = 0; i < g_dch_n; i++)
        if ((old & (1ULL << i)) && !(want & (1ULL << i))) dch_del6(i, domain, f6);
    for (size_t i = 0; i < g_dch_n; i++)
        if ((want & (1ULL << i)) && !(old & (1ULL << i))) dch_add6(i, domain, f6, 0);
    e->sets6 = want;
    e->route6_asserted = now;
}

/* Восстановить DNAT-карту и наборы каналов после (пере)запуска. Возвращает число
 * восстановленных отображений fake→real, в *routed_out — число вновь утверждённых маршрутов.
 *
 * ГЛАВНОЕ ЗДЕСЬ — real_host остаётся у записи ТОЛЬКО если ядро подтвердило отображение.
 * Быстрый путь handle_client_query отвечает клиенту поддельным адресом без похода наверх,
 * когда real_host ненулевой, и считает это безопасным потому, что «real_host запоминается
 * только после ack ядра либо восстановлен rehydrate». Загрузка файла состояния писала третье
 * поле в real_host безусловно, а неудача восстановления его не обнуляла — и при пустой
 * таблице ядра (netlink не открылся, таблица снесена) клиент получал fake-IP в чёрную дыру,
 * пока свежие домены честно шли наверх. Теперь несостоявшееся отображение обнуляет поле, и
 * такой домен идёт долгим путём — как обещает шапка файла про fail-open. */
size_t fakeip_rehydrate(int nk_open, size_t *routed_out) {
    size_t restored = 0, routed = 0;
    for (size_t i = 0; i < g_fakeip.n; i++) {
        struct fakeip_entry *e = &g_fakeip.entries[i];
        if (e->real_host) {
            /* known_real = 0: after a restart the kernel map is empty as far as we know, so
             * this is a plain add (and an EEXIST just means the map survived). */
            if (nk_open == 0 && nft_map_set_element(g_fakeip_map, e->addr, e->real_host, 0) == 0)
                restored++;
            else
                e->real_host = 0;
        }
        /* Половина IPv6 — тем же правилом: настоящий IPv6 остаётся у записи, только если ядро
         * приняло элемент карты fakeip6; иначе быстрый путь AAAA закрыт до нового ответа. */
        if (e->has_real6) {
            uint8_t f6[16];
            fakeip6_of(e->addr, f6);
            if (nk_open != 0 || nft_map_set_element6(g_fakeip6_map, f6, e->real6, NULL) != 0)
                e->has_real6 = 0;
        }
        if (nk_open != 0) continue;
        /* Re-derive the channels for the stored domain and re-assert the permanent route
         * elements. fakeip_route_set запоминает набор, поэтому повторное разрешение имени в те
         * же каналы ничего не стоит. */
        uint64_t all = dch_match_mask(e->domain);
        uint64_t m = dch_fakeip_only(all);
        if (m) { fakeip_route_set(e->domain, m); routed++; }
        /* Поддельный IPv6 ложится в наборы, только если он у имени был выдан (есть настоящий
         * IPv6) и все совпавшие каналы по-прежнему несут IPv6. */
        if (e->has_real6 && m && dch_all_v6(all)) fakeip_route_set6(e->domain, m);
    }
    if (routed_out) *routed_out = routed;
    return restored;
}
