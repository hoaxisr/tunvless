/* TLS 1.3 для QUIC: единственный, кроме src/lib/scrypto.c, файл движка, который видит wolfSSL.
 *
 * ПОЧЕМУ ВТОРОЙ ФАЙЛ, А НЕ ЕЩЁ ОДНА ФУНКЦИЯ В scrypto.c. Слой примитивов (scrypto.h) — это
 * хеши, шифры и проверка подписей без единого типа библиотеки в заголовке: его подключают стенды
 * `make test`, которые wolfSSL не видят вовсе. QUIC устроен иначе. ngtcp2 не берёт примитивы —
 * он берёт сам TLS-стек (рукопожатие TLS 1.3 внутри CRYPTO-кадров, wolfSSL_quic_*), и типы
 * WOLFSSL_CTX и WOLFSSL сквозные: их принимает ngtcp2_crypto_wolfssl, их держит соединение.
 * Этот файл прячет их за указателями void *, чтобы quic.c (ngtcp2, сокеты, потоки) их не
 * видел — ровно как остальной движок не видит wolfSSL. Стенд tests/buildmatch.sh сторожит
 * список файлов, которым заголовки wolfSSL разрешены: их два.
 *
 * Свой TLS 1.3 движка (src/proto/tls/tls13.c) для QUIC не годится: ngtcp2 отдаёт ключи по
 * уровням шифрования (Initial, Handshake, 1-RTT) и ждёт тех же от TLS-стека.
 */
#ifndef STEER_QCSSL_H
#define STEER_QCSSL_H
#include <stddef.h>
#include <stdint.h>

/* Клиентский контекст. insecure — не проверять сертификат; иначе корни из ca_pem либо из ca_file
 * (файл PEM). NULL — не создалось. */
void *qcssl_ctx_client(int insecure, const uint8_t *ca_pem, size_t ca_pem_n, const char *ca_file);
#ifdef QC_WITH_SERVER
/* Серверный контекст стенда: сертификат и ключ — DER. */
void *qcssl_ctx_server(const uint8_t *cert_der, size_t cert_n, const uint8_t *key_der, size_t key_n);
#endif
void  qcssl_ctx_free(void *ctx);

/* Соединение TLS. conn_ref — struct ngtcp2_crypto_conn_ref *, кладётся в прикладные данные (так
 * его достаёт ngtcp2_crypto_wolfssl). sni может быть NULL; при sni != NULL и verify != 0 имя в
 * сертификате сверяется. NULL — не создалось. */
void *qcssl_new(void *ctx, void *conn_ref, const char *sni, const char *alpn, int server, int verify_name);
void  qcssl_free(void *ssl);
/* SHA-256 листового сертификата сервера (DER) — для pinSHA256 у hysteria2. 0 — есть, -1 — нет. */
int   qcssl_peer_sha256(void *ssl, uint8_t out[32]);

#endif
