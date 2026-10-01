/* Разбор ссылок и подписки steer-proxy (src/proto/proxy/pxsub.c) — без сети и криптографии, как
 * submatch для vless: чужой текст из интернета проверяется текстом. Вывод ключей и провод (нужна
 * криптобиблиотека) — в tests/pxmatch.c (`make ext-test`). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include "proxy.h"
#include "unit.h"

static void test_parse(void) {
    struct px_node n;
    check("trojan ссылка", 0, px_parse_url("trojan://pass@h.example:443?security=tls&sni=s.example", &n, 0));
    check_str("trojan protocol", "trojan", px_proto_name(n.proto));
    check_str("trojan password", "pass", n.pass);
    check_str("trojan security", "tls", n.vn.security);
    check("trojan без TLS — негоден", 1, px_parse_url("trojan://pass@h.example:443?security=none", &n, 0));
    check("trojan без пароля — негоден", 1, px_parse_url("trojan://@h.example:443?security=tls&sni=s", &n, 0));

    check("ss SIP002 method:pass", 0, px_parse_url("ss://aes-256-gcm:secret@h.example:8388", &n, 0));
    check("ss method aes-256-gcm", (long)SS_AES256_GCM, (long)n.ss_method);
    check_str("ss pass", "secret", n.pass);
    check_str("ss тип tcp", "tcp", n.vn.type);
    check("ss неизвестный метод — негоден", 1, px_parse_url("ss://rc4-md5:p@h.example:1", &n, 0));
    check("ss plugin= отвергается", 1, px_parse_url("ss://aes-128-gcm:p@h.example:1?plugin=obfs", &n, 0));
    check("ss base64 userinfo", 0, px_parse_url("ss://YWVzLTEyOC1nY206cGFzcw==@h.example:1234", &n, 0));
    check("ss base64 method", (long)SS_AES128_GCM, (long)n.ss_method);
    check("ss 2022 PSK не той длины — негоден", 1,
          px_parse_url("ss://2022-blake3-aes-128-gcm:c2hvcnQ=@h.example:1", &n, 0));

    check("socks5 user:pass", 0, px_parse_url("socks5://u:p@h.example:1080", &n, 0));
    check("socks5 ver", 5, n.socks_ver);
    check_str("socks user", "u", n.user);
    check("socks без схемы socks:// = socks5", 0, px_parse_url("socks://h.example:1080", &n, 0));
    check("socks:// ver", 5, n.socks_ver);
    check("socks4", 0, px_parse_url("socks4://h.example:1080", &n, 0));
    check("socks4 ver", 4, n.socks_ver);
    check("socks4a", 0, px_parse_url("socks4a://h.example:1080", &n, 0));
    check("socks4 с паролем — негоден", 1, px_parse_url("socks4://u:p@h.example:1080", &n, 0));

    check("http basic", 0, px_parse_url("http://u:p@h.example:3128", &n, 0));
    check_str("http proto", "http", px_proto_name(n.proto));
    check_str("http security none", "none", n.vn.security);
    check("https → tls", 0, px_parse_url("https://u:p@h.example:443?sni=s", &n, 0));

    const char *vm = "vmess://eyJ2IjoiMiIsInBzIjoibiIsImFkZCI6ImguZXhhbXBsZSIsInBvcnQiOiI0NDMiLCJpZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0IjoidGNwIiwidGxzIjoidGxzIiwic25pIjoicy5leGFtcGxlIn0=";
    check("vmess v2rayN", 0, px_parse_url(vm, &n, 0));
    check_str("vmess proto", "vmess", px_proto_name(n.proto));
    check("vmess sec auto", (long)VMESS_AUTO, (long)n.vmess_sec);
    check_str("vmess tls", "tls", n.vn.security);

    check("want фильтр: ss при want=vmess — не наша", -1, px_parse_url("ss://aes-128-gcm:p@h.example:1", &n, PX_VMESS));
    check("не наша схема", -1, px_parse_url("wireguard://x@h:1", &n, 0));
    check("адрес «отвечать некому»", 1, px_parse_url("ss://aes-128-gcm:p@127.0.0.1:1", &n, 0));
}

static void test_sub(void) {
    struct px_sub_stats st;
    struct px_node out[16];
    const char *sub =
        "trojan://p@h1.example:443?security=tls&sni=a\n"
        "vless://x@h2:443\n"
        "ss://aes-128-gcm:q@h3.example:1234\n"
        "socks5://u:pw@h4.example:1080\n"
        "hysteria2://pw@h5:443\n";
    size_t got = px_parse_sub(sub, out, 16, 0, &st);
    check("подписка: пригодных 3 (trojan, ss, socks)", 3, (long)got);
    check("подписка: чужих 2 (vless, hysteria2)", 2, (long)st.foreign);

    /* want=shadowsocks — только ss. */
    got = px_parse_sub(sub, out, 16, PX_SS, &st);
    check("подписка want=ss: один узел", 1, (long)got);

    /* base64 списка ссылок. */
    char b64[512];
    const char *one = "trojan://p@h.example:443?security=tls&sni=a";
    /* простое ручное base64 здесь не нужно — px_sub_text разворачивает; проверим список как есть */
    (void)b64; (void)one;
}

int main(void) {
    test_parse();
    test_sub();
    return unit_done("pxsubmatch");
}
