/* Разбор подписки: постквантовые поля Xray-core — encryption (VLESS encryption) и pqv / mldsa65Verify
 * (проверка подписи ML-DSA-65 у Reality). Ссылка vless:// и конфиг Xray в JSON, обе формы settings
 * (vnext/users и упрощённая), негодные значения и причины пропуска.
 *
 * Значения — настоящие, из Xray-core 26.9.9 (tests/sub-pq-samples.h). Криптографии стенду не нужно:
 * годность строки решает vencp.h, а сами обмены проверяет ext-test на настоящей библиотеке и против
 * настоящего Xray (tests/venc.sh). sub.c и vless_proto.c линкуются отдельными объектами (стендов с #include .c из src и так предел). */
#include <stdio.h>
#include <string.h>

#include "vless.h"
#include "vencp.h"
#include "sub-pq-samples.h"

static int g_pass, g_fail;
static void check(const char *what, int ok) {
    if (ok) g_pass++; else { g_fail++; printf("ПРОВАЛ: %s\n", what); }
}
static void check_s(const char *what, const char *want, const char *got) {
    int ok = got && !strcmp(want, got);
    if (!ok) printf("  ожидалось «%s», получено «%s»\n", want, got ? got : "(null)");
    check(what, ok);
}

#define UUID "b831381d-6324-4d53-ad4f-8cda48b30811"

static int url(const char *fmt_tail, struct vless_node *n) {
    static char buf[9000];
    snprintf(buf, sizeof buf, "vless://" UUID "@example.org:443?%s", fmt_tail);
    return vless_parse_url(buf, n);
}

int main(void) {
    struct vless_node n, n2;
    char q[8000];

    /* --- encryption в ссылке --- */
    snprintf(q, sizeof q, "encryption=%s&type=tcp&security=none#a", ENC_X25519);
    check("encryption X25519 (0rtt): узел пригоден", url(q, &n) == 0);
    check_s("encryption хранится строкой как есть", ENC_X25519, n.encryption);

    snprintf(q, sizeof q, "encryption=%s&type=tcp&security=none#a", ENC_MLKEM);
    check("encryption ML-KEM (1579 знаков ключа): узел пригоден", url(q, &n) == 0);
    check_s("длинный ключ не обрезан", ENC_MLKEM, n.encryption);
    check("одинаковое значение — один экземпляр в таблице", url(q, &n2) == 0 && n.encryption == n2.encryption);

    {   /* режимы и набивка, разбор vencp */
        static const char *modes[] = { "native", "xorpub", "random" };
        for (int i = 0; i < 3; i++) {
            char e[400];
            snprintf(e, sizeof e, "mlkem768x25519plus.%s.1rtt.100-111-1111.75-0-111.50-0-3333.YHD4th3rx6hr8R22ZLUA6ivhJdHWNt8bsAcNYrNKxkQ", modes[i]);
            snprintf(q, sizeof q, "encryption=%s&type=tcp&security=none#m", e);
            int rc = url(q, &n);
            struct venc_cfg c;
            int pr = n.encryption ? vencp_parse(n.encryption, &c, NULL) : -1;
            char w[80];
            snprintf(w, sizeof w, "режим %s с набивкой: пригоден и разобран", modes[i]);
            check(w, rc == 0 && pr == 0 && c.xor_mode == i && !c.zero_rtt && c.nkeys == 1 &&
                     c.npad_lens == 2 && c.npad_gaps == 1 && c.lens[0][2] == 1111 && c.gaps[0][0] == 75);
        }
    }

    check("encryption=none — шифрования нет", url("encryption=none&type=tcp&security=none#n", &n) == 0 && n.encryption == NULL);
    check("encryption пусто — шифрования нет", url("encryption=&type=tcp&security=none#n", &n) == 0 && n.encryption == NULL);
    check("параметра нет — шифрования нет", url("type=tcp&security=none#n", &n) == 0 && n.encryption == NULL);

    check("encryption чужого вида — узел пропущен", url("encryption=aes-128-gcm&type=tcp&security=none#n", &n) == 1);
    check_s("причина названа", "encryption не поддержан", n.skip_reason);
    check("режим не из списка — пропущен",
          url("encryption=mlkem768x25519plus.weird.0rtt.YHD4th3rx6hr8R22ZLUA6ivhJdHWNt8bsAcNYrNKxkQ&type=tcp&security=none#n", &n) == 1);
    check("ключ не 32 и не 1184 байта — пропущен",
          url("encryption=mlkem768x25519plus.native.0rtt.YHD4th3rx6hr8R22ZLUA6ivhJdHWNt8bsAcNYrNKx&type=tcp&security=none#n", &n) == 1);
    check("без ключа — пропущен", url("encryption=mlkem768x25519plus.native.0rtt&type=tcp&security=none#n", &n) == 1);
    check("первая набивка короче 35 — пропущен",
          url("encryption=mlkem768x25519plus.native.0rtt.100-10-20.YHD4th3rx6hr8R22ZLUA6ivhJdHWNt8bsAcNYrNKxkQ&type=tcp&security=none#n", &n) == 1);

    /* --- pqv --- */
    snprintf(q, sizeof q, "type=tcp&security=reality&pbk=K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng&sid=01&sni=example.com&fp=chrome&pqv=%s#p", PQV_KEY);
    check("reality с pqv: пригоден", url(q, &n) == 0);
    check_s("pqv хранится целиком (2603 знака)", PQV_KEY, n.pqv);
    snprintf(q, sizeof q, "type=tcp&security=reality&pbk=K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng&sid=01&sni=example.com&pqv=%.100s#p", PQV_KEY);
    check("pqv короткий — пропущен", url(q, &n) == 1);
    check_s("причина pqv названа", "pqv: не ключ ML-DSA-65", n.skip_reason);

    /* --- flow --- */
    check("flow vision-udp443 приводится к vision",
          url("type=tcp&security=reality&pbk=K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng&sid=01&sni=e.com&flow=xtls-rprx-vision-udp443#f", &n) == 0 &&
          !strcmp(n.flow, "xtls-rprx-vision"));

    /* --- конфиг Xray: vnext/users --- */
    {
        static char js[12000];
        snprintf(js, sizeof js,
            "[{\"remarks\":\"PQ\",\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"proxy\","
            "\"settings\":{\"vnext\":[{\"address\":\"example.org\",\"port\":443,\"users\":[{\"id\":\"" UUID "\","
            "\"flow\":\"xtls-rprx-vision\",\"encryption\":\"none\"}]}]},"
            "\"streamSettings\":{\"network\":\"raw\",\"security\":\"reality\",\"realitySettings\":{"
            "\"serverName\":\"example.com\",\"fingerprint\":\"chrome\",\"publicKey\":\"K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng\","
            "\"shortId\":\"01\",\"mldsa65Verify\":\"%s\"}}}]},"
            "{\"remarks\":\"ENC\",\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"proxy\","
            "\"settings\":{\"vnext\":[{\"address\":\"example.net\",\"port\":8443,\"users\":[{\"id\":\"" UUID "\","
            "\"encryption\":\"%s\"}]}]},\"streamSettings\":{\"network\":\"tcp\",\"security\":\"none\"}}]},"
            "{\"remarks\":\"SIMPLE\",\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"proxy\","
            "\"settings\":{\"address\":\"example.io\",\"port\":\"9443\",\"id\":\"" UUID "\",\"encryption\":\"%s\"},"
            "\"streamSettings\":{\"network\":\"tcp\",\"security\":\"none\"}}]}]",
            PQV_KEY, ENC_X25519, ENC_MLKEM);
        struct vless_node out[8];
        struct vless_sub_stats st;
        memset(&st, 0, sizeof st);
        size_t cnt = vless_parse_sub(js, out, 8, &st);
        check("JSON: три узла пригодны", cnt == 3);
        if (cnt == 3) {
            check("JSON: mldsa65Verify → pqv", out[0].pqv && !strcmp(out[0].pqv, PQV_KEY));
            check("JSON: encryption none — нет шифрования", out[0].encryption == NULL);
            check_s("JSON: users[].encryption", ENC_X25519, out[1].encryption);
            check("JSON: упрощённая форма settings — адрес, порт, id", !strcmp(out[2].host, "example.io") && out[2].port == 9443 && !strcmp(out[2].uuid, UUID));
            check_s("JSON: упрощённая форма — encryption", ENC_MLKEM, out[2].encryption);
        }
        check("JSON: пропущенных нет", st.skipped == 0);
    }

    /* --- подписка ссылками: арифметика сходится --- */
    {
        static char sub[20000];
        snprintf(sub, sizeof sub,
                 "vless://" UUID "@a.example:443?encryption=%s&type=tcp&security=none#ok1\n"
                 "vless://" UUID "@b.example:443?encryption=bogus&type=tcp&security=none#bad1\n"
                 "vless://" UUID "@c.example:443?encryption=%s&type=tcp&security=none#ok2\n",
                 ENC_MLKEM, ENC_X25519);
        struct vless_node out[8];
        struct vless_sub_stats st;
        memset(&st, 0, sizeof st);
        size_t cnt = vless_parse_sub(sub, out, 8, &st);
        check("подписка: 2 пригодных, 1 пропущен", cnt == 2 && st.skipped == 1);
        check("подписка: причина в счётчиках", st.reasons_n == 1 && !strcmp(st.reasons[0].reason, "encryption не поддержан") &&
              !strcmp(st.reasons[0].example, "bad1"));
    }


    /* --- то, что клиент не умеет, но сервер требует --- */
    check("tcp headerType=http — пропущен", url("type=tcp&security=none&headerType=http#h", &n) == 1);
    check_s("причина headerType", "tcp headerType=http не поддержан", n.skip_reason);
    check("tcp headerType=none — пригоден", url("type=tcp&security=none&headerType=none#h", &n) == 0);
    check("xhttp с downloadSettings в extra — пропущен",
          url("type=xhttp&security=none&path=/x&extra=%7B%22downloadSettings%22%3A%7B%22address%22%3A%22d.example%22%7D%7D#x", &n) == 1);
    check_s("причина xhttp", "xhttp: обфускация не поддержана", n.skip_reason);
    check("xhttp с xPaddingBytes в extra — пригоден",
          url("type=xhttp&security=none&path=/x&extra=%7B%22xPaddingBytes%22%3A%22100-200%22%7D#x", &n) == 0 && n.pad_from == 100);
    check("xhttp с xPaddingObfsMode=true — пропущен",
          url("type=xhttp&security=none&path=/x&extra=%7B%22xPaddingObfsMode%22%3Atrue%7D#x", &n) == 1);

    /* --- sing-box: outbounds --- */
    {
        static char js[6000];
        snprintf(js, sizeof js,
            "{\"log\":{},\"outbounds\":[{\"type\":\"selector\",\"tag\":\"sel\",\"outbounds\":[\"a\"]},"
            "{\"type\":\"vless\",\"tag\":\"sb-reality\",\"server\":\"example.org\",\"server_port\":443,\"uuid\":\"" UUID "\","
            "\"flow\":\"xtls-rprx-vision\",\"tls\":{\"enabled\":true,\"server_name\":\"example.com\","
            "\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"},\"reality\":{\"enabled\":true,"
            "\"public_key\":\"K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng\",\"short_id\":\"0123456789abcdef\"}}},"
            "{\"type\":\"vless\",\"tag\":\"sb-ws\",\"server\":\"cdn.example.org\",\"server_port\":443,\"uuid\":\"" UUID "\","
            "\"tls\":{\"enabled\":true,\"server_name\":\"cdn.example.org\"},"
            "\"transport\":{\"type\":\"ws\",\"path\":\"/ws\",\"headers\":{\"Host\":[\"front.example.org\"]},"
            "\"max_early_data\":2048,\"early_data_header_name\":\"Sec-WebSocket-Protocol\"}},"
            "{\"type\":\"trojan\",\"tag\":\"t\",\"server\":\"x\",\"server_port\":1}]}");
        struct vless_node out[8];
        struct vless_sub_stats st;
        size_t cnt = vless_parse_sub(js, out, 8, &st);
        check("sing-box: два узла vless", cnt == 2);
        if (cnt == 2) {
            check("sing-box: reality — pbk, sid, sni, fp",
                  !strcmp(out[0].security, "reality") && !strcmp(out[0].pbk, "K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng") &&
                  !strcmp(out[0].sid, "0123456789abcdef") && !strcmp(out[0].sni, "example.com") && !strcmp(out[0].fp, "chrome") &&
                  out[0].port == 443 && !strcmp(out[0].name, "sb-reality") && !strcmp(out[0].flow, "xtls-rprx-vision"));
            check_s("sing-box: ws — путь с ранними данными", "/ws?ed=2048", out[1].path);
            check_s("sing-box: ws — Host из массива", "front.example.org", out[1].http_host);
            check("sing-box: tls и тип ws", !strcmp(out[1].security, "tls") && !strcmp(out[1].type, "ws"));
        }
    }

    /* --- Clash / Mihomo --- */
    {
        static char y[9000];
        snprintf(y, sizeof y,
            "port: 7890\nmixed-port: 7891\nproxies:\n"
            "  - name: \"clash-block\"   # комментарий\n"
            "    type: vless\n    server: example.org\n    port: 443\n    uuid: " UUID "\n"
            "    network: tcp\n    tls: true\n    udp: true\n    flow: xtls-rprx-vision\n"
            "    servername: example.com\n    client-fingerprint: chrome\n    encryption: \"\"\n"
            "    alpn:\n      - h2\n      - http/1.1\n"
            "    reality-opts:\n      public-key: K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng\n      short-id: 0123456789abcdef\n"
            "  - {name: clash-flow, type: vless, server: cdn.example.org, port: 8443, uuid: " UUID ", network: ws, tls: true, servername: cdn.example.org, "
            "ws-opts: {path: /ws, headers: {Host: front.example.org}, max-early-data: 2048, early-data-header-name: Sec-WebSocket-Protocol}}\n"
            "  - name: clash-enc\n    type: vless\n    server: enc.example.org\n    port: 9443\n    uuid: " UUID "\n    network: tcp\n    encryption: %s\n"
            "  - name: ss-node\n    type: ss\n    server: s\n    port: 1\n    cipher: aes-128-gcm\n    password: p\n"
            "  - name: grpc-node\n    type: vless\n    server: g.example.org\n    port: 443\n    uuid: " UUID "\n    network: grpc\n    tls: true\n"
            "    grpc-opts:\n      grpc-service-name: svc\n"
            "proxy-groups:\n  - name: auto\n    type: select\n    proxies:\n      - clash-block\n", ENC_X25519);
        struct vless_node out[8];
        struct vless_sub_stats st;
        size_t cnt = vless_parse_sub(y, out, 8, &st);
        check("Clash: четыре узла vless, один чужой", cnt == 4 && st.foreign == 1);
        if (cnt == 4) {
            check("Clash (блок): reality, sni, fp, flow, имя без комментария",
                  !strcmp(out[0].security, "reality") && !strcmp(out[0].sni, "example.com") && !strcmp(out[0].fp, "chrome") &&
                  !strcmp(out[0].pbk, "K4ALTVxNnrDTywBj_Stb5bomQ21QlSWOlGGT44n9Nng") && !strcmp(out[0].sid, "0123456789abcdef") &&
                  !strcmp(out[0].flow, "xtls-rprx-vision") && !strcmp(out[0].name, "clash-block") && out[0].encryption == NULL);
            check("Clash (поток): ws, путь, Host, ранние данные",
                  !strcmp(out[1].type, "ws") && !strcmp(out[1].path, "/ws?ed=2048") && !strcmp(out[1].http_host, "front.example.org") &&
                  !strcmp(out[1].security, "tls") && out[1].port == 8443);
            check_s("Clash: encryption", ENC_X25519, out[2].encryption);
            check("Clash: grpc-service-name", !strcmp(out[3].type, "grpc") && !strcmp(out[3].service, "svc"));
        }
        char dec[64];
        check("Clash распознан как текст, а не base64", vless_sub_text(y, strlen(y), dec, sizeof dec) == y);
    }

    printf(g_fail ? "ПРОВАЛОВ: %d (прошло %d)\n" : "subpq: всё совпало (%d проверок)\n", g_fail ? g_fail : g_pass, g_pass);
    return g_fail ? 1 : 0;
}
