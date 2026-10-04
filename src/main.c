/* tunvless: a TUN device whose TCP and UDP traffic goes to a VLESS server.
 *
 * Everything here is the command line around three pieces: the node (a vless:// link, or a file of
 * links or an Xray / sing-box / Clash config — proto/vless/sub.c), the stack that turns the
 * device's packets into flows (tunnel/stack.c) and the VLESS dialer that carries each flow to the
 * node (proto/vless/vldial.c). The process lives as long as the device: a signal ends both, and
 * the kernel removes the device and every route into it when the process exits.
 *
 * Exit codes: 2 — the command line or the node is wrong (restarting will not help); 1 — the
 * tunnel did not come up or stopped carrying traffic; 0 — stopped by SIGINT, SIGTERM or SIGHUP.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "vless.h"
#include "client.h"
#include "vldial.h"
#include "stack.h"
#include "ifcfg.h"
#include "transport.h"
#include "roots.h"

#ifndef TUNVLESS_VERSION
#define TUNVLESS_VERSION "dev"
#endif

#define LOG_W "tunvless[warn]: "
#define LOG_I "tunvless[info]: "

#define ROUTES_MAX 64
#define RETRY_MAX_S 60

struct route { uint32_t dst; int prefix; };

static struct {
    const char *source;
    int node;                   /* -1 — not chosen on the command line */
    int list, probe, no_probe, no_retry, insecure;
    const char *ca;
    const char *bind_dev;
    uint32_t mark;
    uint32_t table;
    int silence_s, timeout_s;
    struct tun_cfg tc;
    struct route routes[ROUTES_MAX];
    int routes_n;
} g = {
    .node = -1,
    .silence_s = 20,
    .timeout_s = 8,
    .tc = { .dev = "tunvless0", .prefix = 32 },
};

static struct vless_node *g_nodes;
static size_t g_cnt;
static int g_single;            /* the node came as a link, not from a file */

static void usage(FILE *f) {
    fprintf(f,
"Usage: tunvless [options] <vless://link | file>\n"
"\n"
"Creates a TUN device and carries its TCP and UDP traffic to a VLESS server\n"
"(Reality, TLS or none; tcp, grpc, xhttp, ws or httpupgrade; Vision; VLESS encryption).\n"
"\n"
"The node:\n"
"  vless://...            a VLESS link\n"
"  file                   vless:// links (plain or base64), or an Xray, sing-box or\n"
"                         Clash config with VLESS outbounds\n"
"  -n, --node N           use node N of the file (from 0, among usable nodes); default:\n"
"                         the first one that answers a probe\n"
"  -l, --list             print the usable nodes and exit\n"
"  -p, --probe            check the node (or every node of the file) and exit\n"
"      --no-probe         take the first node of the file without checking it\n"
"      --insecure         accept allowInsecure nodes; do not verify certificates of\n"
"                         security=tls nodes\n"
"      --ca FILE          trusted roots (PEM) for security=tls\n"
"\n"
"The device:\n"
"  -d, --dev NAME         device name (default tunvless0)\n"
"  -a, --addr CIDR        device address (default 198.51.100.1/32)\n"
"  -r, --route CIDR       route CIDR into the device once it is up; repeatable;\n"
"                         \"default\" means 0.0.0.0/1 and 128.0.0.0/1\n"
"  -T, --table N          routing table for --route (default main)\n"
"\n"
"Keeping the tunnel's own connections out of the tunnel (without either, a --route\n"
"that covers the server gets a host route to the server through its current gateway):\n"
"  -m, --mark N           SO_MARK on sockets to the server\n"
"  -b, --bind-dev IFACE   send sockets to the server out of IFACE (SO_BINDTODEVICE)\n"
"\n"
"Other:\n"
"  -t, --timeout S        probe and connect timeout, seconds (default 8)\n"
"      --silence S        reset a connection whose server stays silent for S seconds\n"
"                         (default 20, 0 — never)\n"
"      --no-retry         exit when the node cannot be resolved or none answers,\n"
"                         instead of retrying\n"
"  -V, --version\n"
"  -h, --help\n");
}

static int parse_uint(const char *s, uint32_t *out) {
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, 0);
    if (!*s || *end || errno || v > 0xffffffffUL) return -1;
    *out = (uint32_t)v;
    return 0;
}

static int add_route(const char *s) {
    if (!strcmp(s, "default")) return add_route("0.0.0.0/1") || add_route("128.0.0.0/1");
    if (g.routes_n >= ROUTES_MAX) {
        fprintf(stderr, "tunvless: more than %d routes\n", ROUTES_MAX);
        return -1;
    }
    struct route *r = &g.routes[g.routes_n];
    if (ifcfg_parse_cidr(s, &r->dst, &r->prefix) != 0) {
        fprintf(stderr, "tunvless: %s is not an IPv4 prefix\n", s);
        return -1;
    }
    g.routes_n++;
    return 0;
}

enum { OPT_NO_PROBE = 256, OPT_INSECURE, OPT_CA, OPT_SILENCE, OPT_NO_RETRY };

static int parse_args(int argc, char **argv) {
    static const struct option opts[] = {
        { "node",     required_argument, NULL, 'n' },
        { "list",     no_argument,       NULL, 'l' },
        { "probe",    no_argument,       NULL, 'p' },
        { "no-probe", no_argument,       NULL, OPT_NO_PROBE },
        { "insecure", no_argument,       NULL, OPT_INSECURE },
        { "ca",       required_argument, NULL, OPT_CA },
        { "dev",      required_argument, NULL, 'd' },
        { "addr",     required_argument, NULL, 'a' },
        { "route",    required_argument, NULL, 'r' },
        { "table",    required_argument, NULL, 'T' },
        { "mark",     required_argument, NULL, 'm' },
        { "bind-dev", required_argument, NULL, 'b' },
        { "timeout",  required_argument, NULL, 't' },
        { "silence",  required_argument, NULL, OPT_SILENCE },
        { "no-retry", no_argument,       NULL, OPT_NO_RETRY },
        { "version",  no_argument,       NULL, 'V' },
        { "help",     no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };
    const char *addr = "198.51.100.1/32";
    uint32_t v;
    int c;
    while ((c = getopt_long(argc, argv, "n:lpd:a:r:T:m:b:t:Vh", opts, NULL)) != -1) {
        switch (c) {
        case 'n':
            if (parse_uint(optarg, &v) != 0 || v > 1000000) goto bad;
            g.node = (int)v;
            break;
        case 'l': g.list = 1; break;
        case 'p': g.probe = 1; break;
        case OPT_NO_PROBE: g.no_probe = 1; break;
        case OPT_INSECURE: g.insecure = 1; break;
        case OPT_CA: g.ca = optarg; break;
        case 'd':
            if (!optarg[0] || strlen(optarg) >= IFNAMSIZ) {
                fprintf(stderr, "tunvless: device name must be 1..%d characters\n", IFNAMSIZ - 1);
                return 2;
            }
            g.tc.dev = optarg;
            break;
        case 'a': addr = optarg; break;
        case 'r': if (add_route(optarg) != 0) return 2; break;
        case 'T': if (parse_uint(optarg, &g.table) != 0) goto bad; break;
        case 'm': if (parse_uint(optarg, &g.mark) != 0) goto bad; break;
        case 'b':
            if (!optarg[0] || strlen(optarg) >= IFNAMSIZ) goto bad;
            g.bind_dev = optarg;
            break;
        case 't':
            if (parse_uint(optarg, &v) != 0 || v == 0 || v > 600) goto bad;
            g.timeout_s = (int)v;
            break;
        case OPT_SILENCE:
            if (parse_uint(optarg, &v) != 0 || v > 3600) goto bad;
            g.silence_s = (int)v;
            break;
        case OPT_NO_RETRY: g.no_retry = 1; break;
        case 'V': printf("tunvless %s\n", TUNVLESS_VERSION); exit(0);
        case 'h': usage(stdout); exit(0);
        default: usage(stderr); return 2;
        }
    }
    if (optind != argc - 1) { usage(stderr); return 2; }
    g.source = argv[optind];
    if (ifcfg_parse_cidr(addr, &g.tc.addr, &g.tc.prefix) != 0) {
        fprintf(stderr, "tunvless: --addr %s is not an IPv4 address\n", addr);
        return 2;
    }
    return 0;
bad:
    fprintf(stderr, "tunvless: bad option value: %s\n", optarg);
    return 2;
}

/* ---- the node ------------------------------------------------------------------------- */

static int load_file(void) {
    struct vless_sub_stats st;
    g_nodes = vless_load_sub(g.source, &g_cnt, &st);
    if (!g_nodes) {
        fprintf(stderr, "tunvless: %s cannot be read\n", g.source);
        return 2;
    }
    if (g_cnt == 0 || st.skipped)
        fprintf(stderr, "%s%s: %zu usable VLESS nodes (skipped %zu, other protocols %zu)\n",
                g_cnt ? LOG_I : LOG_W, g.source, g_cnt, st.skipped, st.foreign);
    for (size_t i = 0; i < st.reasons_n; i++)
        fprintf(stderr, "%s  %s — %zu node(s)%s%s\n", g_cnt ? LOG_I : LOG_W, st.reasons[i].reason,
                st.reasons[i].count, st.reasons[i].example[0] ? ", e.g. " : "",
                st.reasons[i].example);
    return g_cnt ? 0 : 2;
}

static int load_nodes(void) {
    if (!strncmp(g.source, "vless://", 8)) {
        g_nodes = calloc(1, sizeof(*g_nodes));
        if (!g_nodes) return 1;
        int r = vless_parse_url(g.source, g_nodes);
        if (r < 0) {
            fprintf(stderr, "tunvless: not a vless:// link\n");
            return 2;
        }
        if (r > 0) {
            fprintf(stderr, "tunvless: the link cannot be used: %s\n", g_nodes->skip_reason);
            return 2;
        }
        g_cnt = 1;
        g_single = 1;
    } else {
        int rc = load_file();
        if (rc) return rc;
    }
    if (g.node >= (int)g_cnt) {
        fprintf(stderr, "tunvless: there is no node %d (usable nodes: %zu)\n", g.node, g_cnt);
        return 2;
    }
    return 0;
}

static int cmd_list(void) {
    for (size_t i = 0; i < g_cnt; i++) {
        const struct vless_node *n = &g_nodes[i];
        printf("%zu\t%s\t%s:%u\t%s/%s%s%s\n", i, n->name, n->host, n->port, n->type, n->security,
               n->flow[0] ? " vision" : "", n->encryption ? " encryption" : "");
    }
    return 0;
}

/* --probe: the same check as at startup, with timings. */
static int cmd_probe(void) {
    int found = 0;
    for (size_t i = 0; i < g_cnt; i++) {
        if (g.node >= 0 && (int)i != g.node) continue;
        char why[256] = "";
        int hs = -1, ttfb = -1;
        int rc = vless_probe_timed(&g_nodes[i], g.timeout_s, why, sizeof(why), &hs, &ttfb);
        if (rc == 0) {
            found = 1;
            printf("%zu\t%s\tok\thandshake %d ms, first byte %d ms\n", i, g_nodes[i].name, hs, ttfb);
        } else {
            printf("%zu\t%s\tfailed\t%s\n", i, g_nodes[i].name, why);
        }
        fflush(stdout);
    }
    return found ? 0 : 1;
}

/* Wait before the next attempt: 5 s, doubling up to a minute. 0 — do not retry. */
static int retry_wait(unsigned *step, const char *what) {
    if (g.no_retry) return 0;
    fprintf(stderr, LOG_I "%s — next attempt in %u s\n", what, *step);
    sleep(*step);
    *step = *step * 2 > RETRY_MAX_S ? RETRY_MAX_S : *step * 2;
    return 1;
}

/* The node to bring the device up with. Named one (--node, or the link itself) is not probed —
 * the person chose it; otherwise the first node of the file that answers. NULL — none. */
static const struct vless_node *choose_node(void) {
    if (g.node >= 0) return &g_nodes[g.node];
    if (g_single || g.no_probe) return &g_nodes[0];
    unsigned step = 5;
    for (;;) {
        for (size_t i = 0; i < g_cnt; i++) {
            char why[256] = "";
            if (vless_probe(&g_nodes[i], g.timeout_s, why, sizeof(why)) == 0) {
                fprintf(stderr, LOG_I "chose %s (%s)\n", g_nodes[i].name, why);
                return &g_nodes[i];
            }
            fprintf(stderr, LOG_I "%s — %s\n", g_nodes[i].name, why);
        }
        if (!retry_wait(&step, "no node answered")) return NULL;
    }
}

/* Resolve the node's name once, before any route points into the device (trdial.c says why). */
static int pin_node(const struct vless_node *n) {
    unsigned step = 5;
    for (;;) {
        int k = transport_pin_host(n->host);
        if (k > 0) return 0;
        char what[192];
        snprintf(what, sizeof(what), "%s does not resolve", n->host);
        if (!retry_wait(&step, what)) {
            fprintf(stderr, LOG_W "%s\n", what);
            return -1;
        }
    }
}

/* ---- routes --------------------------------------------------------------------------- */

/* Host routes added for the server (keep_server_out). Unlike the routes into the device, they go
 * through a real interface and would outlive the process, so they are removed on the way out. */
#define KEPT_MAX 16
static struct kept { uint32_t dst, gw; unsigned oif; } g_kept[KEPT_MAX];
static int g_kept_n;
static pthread_mutex_t g_kept_mu = PTHREAD_MUTEX_INITIALIZER;

static void kept_remove(void) {
    pthread_mutex_lock(&g_kept_mu);
    for (int i = 0; i < g_kept_n; i++)
        ifcfg_route_unvia(g_kept[i].dst, g_kept[i].gw, g_kept[i].oif, g.table);
    g_kept_n = 0;
    pthread_mutex_unlock(&g_kept_mu);
}

static int covered(uint32_t a, const struct route *r) {
    uint32_t mask = r->prefix ? htonl(~0u << (32 - r->prefix)) : 0;
    return (a & mask) == (r->dst & mask);
}

/* Without --mark and --bind-dev, sockets to the server follow the routing table, so a route that
 * covers the server would send the tunnel's own connections into the tunnel. Such addresses keep
 * the route they have now, as a host route next to ours. */
static void keep_server_out(const struct vless_node *n) {
    uint32_t addrs[16];
    int k = transport_pinned_addrs(n->host, addrs, 16);
    for (int i = 0; i < k; i++) {
        int hit = 0;
        for (int j = 0; j < g.routes_n && !hit; j++) hit = covered(addrs[i], &g.routes[j]);
        if (!hit) continue;
        char a[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addrs[i], a, sizeof(a));
        uint32_t gw;
        unsigned oif;
        int rc = ifcfg_route_get(addrs[i], &gw, &oif);
        if (rc == 1) continue;                  /* an address of this machine */
        /* Added and recorded under one lock: a stop in between would otherwise leave the route. */
        pthread_mutex_lock(&g_kept_mu);
        if (rc == 0 && g_kept_n >= KEPT_MAX) rc = -ENOSPC;
        if (rc == 0) rc = ifcfg_route_via(addrs[i], gw, oif, g.table);
        if (rc == 0) g_kept[g_kept_n++] = (struct kept){ addrs[i], gw, oif };
        pthread_mutex_unlock(&g_kept_mu);
        /* The table already has a host route for the server (the person's own): it stands, and it
         * is not ours to remove. */
        if (rc == -EEXIST) {
            fprintf(stderr, LOG_I "server %s already has a host route — left as it is\n", a);
            continue;
        }
        if (rc != 0)
            fprintf(stderr, LOG_W "server %s is covered by --route, and its own route was not kept "
                            "(%s) — use --bind-dev or --mark\n", a, strerror(-rc));
        else
            fprintf(stderr, LOG_I "server %s keeps its route outside the tunnel\n", a);
    }
}

static void on_ready(void *arg, const char *dev) {
    const struct vless_node *n = arg;
    if (g.routes_n && !g.mark && !g.bind_dev) keep_server_out(n);
    int ok = 0;
    for (int i = 0; i < g.routes_n; i++) {
        int rc = ifcfg_route_add(dev, g.routes[i].dst, g.routes[i].prefix, g.table);
        char a[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &g.routes[i].dst, a, sizeof(a));
        if (rc != 0)
            fprintf(stderr, LOG_W "route %s/%d into %s not added: %s\n", a, g.routes[i].prefix,
                    dev, strerror(-rc));
        else
            ok++;
    }
    if (g.routes_n)
        fprintf(stderr, LOG_I "%s: %d of %d routes added%s\n", dev, ok, g.routes_n,
                g.table ? " (table set with --table)" : "");
}

/* ---- stopping ------------------------------------------------------------------------- */

/* SIGINT, SIGTERM and SIGHUP are blocked in every thread (the stack's threads inherit the mask) and
 * taken by this one: it removes the server's host routes and ends the process. The device and the
 * routes into it go with the process. */
static sigset_t g_stop_set;

static void *stop_waiter(void *arg) {
    (void)arg;
    int sig = 0;
    if (sigwait(&g_stop_set, &sig) != 0) return NULL;
    fprintf(stderr, LOG_I "signal %d: stopping\n", sig);
    kept_remove();
    _exit(0);
}

static void stop_on_signals(void) {
    sigemptyset(&g_stop_set);
    sigaddset(&g_stop_set, SIGINT);
    sigaddset(&g_stop_set, SIGTERM);
    sigaddset(&g_stop_set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &g_stop_set, NULL);
    pthread_t t;
    if (pthread_create(&t, NULL, stop_waiter, NULL) == 0) {
        pthread_detach(t);
    } else {
        /* No thread to take them: leave the signals to their default action. */
        pthread_sigmask(SIG_UNBLOCK, &g_stop_set, NULL);
    }
}

int main(int argc, char **argv) {
    /* A write to a socket the server has already closed must be an error, not the end of the
     * process (and of every other connection with it). */
    signal(SIGPIPE, SIG_IGN);
    int rc = parse_args(argc, argv);
    if (rc) return rc;

    /* Before the nodes are parsed: whether allowInsecure nodes are usable depends on it. */
    vless_set_insecure(g.insecure);
    if (g.ca) tls_set_cert_roots(g.ca);
    /* Before the first connection, so probes go the way the tunnel will. */
    transport_set_sock_mark(g.mark, g.mark != 0);
    transport_set_bind_dev(g.bind_dev);

    rc = load_nodes();
    if (rc) return rc;
    if (g.list) return cmd_list();
    if (g.probe) return cmd_probe();

    stop_on_signals();
    fprintf(stderr, LOG_I "tunvless %s\n", TUNVLESS_VERSION);
    if (g.insecure)
        fprintf(stderr, LOG_W "--insecure: certificates of security=tls nodes are NOT verified\n");
    const struct vless_node *node = choose_node();
    if (!node) {
        fprintf(stderr, LOG_W "no node answered\n");
        return 1;
    }
    if (pin_node(node) != 0) return 1;
    rc = vless_tunnel_run(&g.tc, node, g.silence_s, on_ready, (void *)node);
    kept_remove();
    return rc;
}
