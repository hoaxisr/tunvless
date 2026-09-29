/* TLS 1.3 для QUIC поверх wolfSSL — см. qcssl.h (зачем отдельный файл и почему void *). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#include "qcssl.h"
#include "certverify.h"

/* Потолок размера файла корней — то же рассуждение, что у certverify.c (roots_load): путь может
 * оказаться /dev/zero, и «прочесть всё» не должно значить «съесть память роутера». ca-bundle весит
 * около 200 КБ. */
#define QCSSL_ROOTS_MAX (1024 * 1024)

static unsigned char *read_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    unsigned char *buf = malloc(QCSSL_ROOTS_MAX + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, QCSSL_ROOTS_MAX + 1, f);
    fclose(f);
    if (got == 0 || got > QCSSL_ROOTS_MAX) { free(buf); return NULL; }
    *n = got;
    return buf;
}

void *qcssl_ctx_client(int insecure, const uint8_t *ca_pem, size_t ca_pem_n, const char *ca_file) {
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) return NULL;
    /* Версии, билеты сессии и кодовая точка параметров транспорта выставляет ngtcp2. */
    if (ngtcp2_crypto_wolfssl_configure_client_context(ctx) != 0) goto fail;
    if (insecure) {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
        return ctx;
    }
    unsigned char *own = NULL;
    if (!ca_pem) {
        size_t n = 0;
        own = read_file(ca_file && ca_file[0] ? ca_file : CERTV_DEFAULT_ROOTS, &n);
        if (!own) goto fail;              /* нет хранилища корней: проверить нечем — отказ, а не «без проверки» */
        ca_pem = own;
        ca_pem_n = n;
    }
    int rc = wolfSSL_CTX_load_verify_buffer(ctx, ca_pem, (long)ca_pem_n, WOLFSSL_FILETYPE_PEM);
    free(own);
    if (rc != WOLFSSL_SUCCESS) goto fail;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    return ctx;
fail:
    wolfSSL_CTX_free(ctx);
    return NULL;
}

#ifdef QC_WITH_SERVER
void *qcssl_ctx_server(const uint8_t *cert_der, size_t cert_n, const uint8_t *key_der, size_t key_n) {
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!ctx) return NULL;
    if (ngtcp2_crypto_wolfssl_configure_server_context(ctx) != 0 ||
        wolfSSL_CTX_use_certificate_buffer(ctx, cert_der, (long)cert_n, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_buffer(ctx, key_der, (long)key_n, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}
#endif

void qcssl_ctx_free(void *ctx) {
    if (ctx) wolfSSL_CTX_free(ctx);
}

void *qcssl_new(void *ctx, void *conn_ref, const char *sni, const char *alpn, int server, int verify_name) {
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) return NULL;
    wolfSSL_set_app_data(ssl, conn_ref);
    if (server) wolfSSL_set_accept_state(ssl); else wolfSSL_set_connect_state(ssl);
    if (alpn && alpn[0]) {
        /* Несовпадение ALPN — отказ рукопожатия (как у настоящих серверов), а не «ну ладно». */
        if (wolfSSL_UseALPN(ssl, (char *)alpn, (unsigned)strlen(alpn), WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS)
            goto fail;
    }
    if (!server && sni && sni[0]) {
        if (wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, sni, (unsigned short)strlen(sni)) != WOLFSSL_SUCCESS)
            goto fail;
        if (verify_name && wolfSSL_check_domain_name(ssl, sni) != WOLFSSL_SUCCESS)
            goto fail;
    }
    return ssl;
fail:
    wolfSSL_free(ssl);
    return NULL;
}

void qcssl_free(void *ssl) {
    if (ssl) wolfSSL_free(ssl);
}
