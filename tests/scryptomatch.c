/* Слой примитивов (src/lib/scrypto.c) против известных векторов — стенд, без которого переезд
 * криптобиблиотеки проверялся бы только рукопожатием с живым сервером.
 *
 * ЗАЧЕМ ВЕКТОРЫ, А НЕ «РУКОПОЖАТИЕ ПРОШЛО». Ошибка в криптографии не выглядит как ошибка. Сервер
 * Reality на неверный аутентификатор не отвечает отказом — он молча отдаёт маскировочный сайт; не
 * тот X25519 у двух концов xsteer даёт «рукопожатие не сходится» без единой подсказки; порча гаммы
 * MTProto у моста tgws выглядит как «Telegram не отвечает». Поэтому каждый примитив слоя сверяется
 * здесь с опубликованными векторами (RFC и NIST), а проверка цепочки и подписей — с сертификатами
 * и подписями, которые выпустил OpenSSL (tests/scrypto-pki.h), то есть независимо от библиотеки,
 * которую проверяем.
 *
 * Векторы:
 *   SHA-256/384/512  — FIPS 180-4 (примеры «abc» и двухблочный), плюс клон контекста посередине;
 *   HMAC             — RFC 4231, случаи 1 и 2;
 *   HKDF             — RFC 5869, случаи 1 и 3 (с солью и без соли и info);
 *   AES-GCM          — спецификация GCM (McGrew–Viega), случаи 2, 4, 14 и 16;
 *   ChaCha20-Poly1305 — RFC 8439 §2.8.2;
 *   X25519           — RFC 7748 §5.2 (неприжатый скаляр), §5.2 итерации, §6.1 (Алиса и Боб);
 *   AES-256-CTR      — NIST SP 800-38A F.5.5, целиком и кусками разной длины.
 * Плюс то, что векторы не ловят: работа НА МЕСТЕ на размерах записи TLS (до 16401 байта — граница,
 * на которой когда-то ломался тег, см. прежний tests/gcm-size.c), отказ на подменённом теге и AAD,
 * нулевой секрет X25519 на точке малого порядка, отсутствие «хвоста» временных промежуточных после
 * проверки цепочки и параллельные проверки из нескольких потоков.
 *
 * Библиотека нужна настоящая, поэтому стенд — в `make ext-test` (tests/ext-test.sh), а не в
 * `make test`. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>

#include "scrypto.h"
#include "unit.h"
#include "scrypto-pki.h"

static size_t unhex(const char *s, unsigned char *out, size_t cap) {
    size_t n = 0;
    for (; s[0] && s[1]; s += 2) {
        unsigned hi, lo;
        if (sscanf(s, "%1x%1x", &hi, &lo) != 2 || n >= cap) break;
        out[n++] = (unsigned char)(hi << 4 | lo);
    }
    return n;
}

static void check_bytes(const char *what, const char *want_hex, const unsigned char *got, size_t n) {
    unsigned char want[512];
    size_t wn = unhex(want_hex, want, sizeof(want));
    if (wn != n) { check(what, (long)wn, (long)n); return; }
    check_mem(what, want, got, n);
}

/* ---- хеши, HMAC, HKDF ------------------------------------------------------------------------ */

static void test_hash(void) {
    unsigned char out[64];
    const char *abc = "abc";
    const char *two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    check("SHA-256(abc): код", 0, sc_hash(SC_SHA256, abc, 3, out));
    check_bytes("SHA-256(abc)", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", out, 32);
    sc_hash(SC_SHA256, two, strlen(two), out);
    check_bytes("SHA-256(двухблочный)", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", out, 32);
    sc_hash(SC_SHA256, "", 0, out);
    check_bytes("SHA-256(пусто)", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", out, 32);
    sc_hash(SC_SHA384, abc, 3, out);
    check_bytes("SHA-384(abc)", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                "8086072ba1e7cc2358baeca134c825a7", out, 48);
    sc_hash(SC_SHA512, abc, 3, out);
    check_bytes("SHA-512(abc)", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", out, 64);

    /* Клон посередине — ровно то, что делает транскрипт TLS 1.3: снять хеш и продолжить. */
    static const enum sc_hash hs[] = { SC_SHA256, SC_SHA384 };
    for (size_t i = 0; i < 2; i++) {
        struct sc_hash_ctx a, b;
        unsigned char w[64], x[64], y[64];
        sc_hash(hs[i], abc, 3, w);
        sc_hash_init(&a, hs[i]);
        sc_hash_update(&a, "ab", 2);
        check(hs[i] == SC_SHA256 ? "клон SHA-256: код" : "клон SHA-384: код", 0, sc_hash_clone(&b, &a));
        sc_hash_update(&a, "c", 1);
        sc_hash_update(&b, "c", 1);
        sc_hash_final(&a, x);
        sc_hash_final(&b, y);
        check_mem(hs[i] == SC_SHA256 ? "клон SHA-256: оригинал продолжился" : "клон SHA-384: оригинал продолжился",
                  w, x, sc_hash_len(hs[i]));
        check_mem(hs[i] == SC_SHA256 ? "клон SHA-256: копия независима" : "клон SHA-384: копия независима",
                  w, y, sc_hash_len(hs[i]));
        sc_hash_free(&a);
        sc_hash_free(&b);
    }
    check("длина хеша неизвестного алгоритма — 0", 0, (long)sc_hash_len((enum sc_hash)9));
}

static void test_hmac(void) {
    unsigned char key[20], out[64];
    memset(key, 0x0b, sizeof(key));
    const char *hi = "Hi There";
    sc_hmac(SC_SHA256, key, 20, hi, 8, out);
    check_bytes("HMAC-SHA256 RFC 4231 #1", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", out, 32);
    sc_hmac(SC_SHA384, key, 20, hi, 8, out);
    check_bytes("HMAC-SHA384 RFC 4231 #1", "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
                "faea9ea9076ede7f4af152e8b2fa9cb6", out, 48);
    sc_hmac(SC_SHA512, key, 20, hi, 8, out);
    check_bytes("HMAC-SHA512 RFC 4231 #1", "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", out, 64);
    const char *q = "what do ya want for nothing?";
    sc_hmac(SC_SHA256, "Jefe", 4, q, strlen(q), out);
    check_bytes("HMAC-SHA256 RFC 4231 #2", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", out, 32);
    unsigned char two[32];
    sc_hmac2(SC_SHA256, "Jefe", 4, q, 10, q + 10, strlen(q) - 10, two);
    check_mem("HMAC двумя кусками = одним", out, two, 32);
}

static void test_hkdf(void) {
    unsigned char ikm[22], salt[13], info[10], prk[64], okm[42];
    memset(ikm, 0x0b, sizeof(ikm));
    for (unsigned i = 0; i < sizeof(salt); i++) salt[i] = (unsigned char)i;
    for (unsigned i = 0; i < sizeof(info); i++) info[i] = (unsigned char)(0xf0 + i);

    check("HKDF #1 extract: код", 0, sc_hkdf_extract(SC_SHA256, salt, 13, ikm, 22, prk));
    check_bytes("HKDF #1 PRK", "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", prk, 32);
    check("HKDF #1 expand: код", 0, sc_hkdf_expand(SC_SHA256, prk, 32, info, 10, okm, 42));
    check_bytes("HKDF #1 OKM", "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865", okm, 42);
    memset(okm, 0, sizeof(okm));
    sc_hkdf(SC_SHA256, salt, 13, ikm, 22, info, 10, okm, 42);
    check_bytes("HKDF #1 одним вызовом", "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865", okm, 42);

    /* Без соли и info — случай, на котором стоят вывод ключей xsteer и «derived» TLS 1.3. */
    sc_hkdf_extract(SC_SHA256, NULL, 0, ikm, 22, prk);
    check_bytes("HKDF #3 PRK (без соли)", "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", prk, 32);
    sc_hkdf_expand(SC_SHA256, prk, 32, NULL, 0, okm, 42);
    check_bytes("HKDF #3 OKM (без info)", "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                "9d201395faa4b61a96c8", okm, 42);
    static unsigned char big[255 * 32 + 1];
    check("HKDF: вывод длиннее 255 блоков — отказ", SC_EINVAL,
          sc_hkdf_expand(SC_SHA256, prk, 32, NULL, 0, big, sizeof(big)));
}

/* ---- AEAD ------------------------------------------------------------------------------------ */

struct gcm_case {
    const char *name, *key, *iv, *p, *a, *c, *t;
};

static void aead_case(const char *name, enum sc_aead_alg alg, const char *key_hex, const char *iv_hex,
                      const char *p_hex, const char *a_hex, const char *c_hex, const char *t_hex) {
    unsigned char key[32], iv[12], p[128], a[64], buf[128], tag[16];
    char what[96];
    unhex(key_hex, key, sizeof(key));
    unhex(iv_hex, iv, sizeof(iv));
    size_t pn = unhex(p_hex, p, sizeof(p)), an = unhex(a_hex, a, sizeof(a));
    struct sc_aead k;
    snprintf(what, sizeof(what), "%s: ключ", name);
    check(what, 0, sc_aead_setkey(&k, alg, key));
    memcpy(buf, p, pn);
    snprintf(what, sizeof(what), "%s: шифрование на месте", name);
    check(what, 0, sc_aead_seal(&k, iv, a, an, buf, pn, tag));
    snprintf(what, sizeof(what), "%s: шифротекст", name);
    check_bytes(what, c_hex, buf, pn);
    snprintf(what, sizeof(what), "%s: тег", name);
    check_bytes(what, t_hex, tag, 16);
    snprintf(what, sizeof(what), "%s: расшифровка", name);
    check(what, 0, sc_aead_open(&k, iv, a, an, buf, pn, tag));
    snprintf(what, sizeof(what), "%s: открытый текст вернулся", name);
    check_mem(what, p, buf, pn);
    /* Подмена: тег и AAD. Отказ обязан быть именно «не сошлось», а не общий сбой. */
    unsigned char bad[16];
    memcpy(bad, tag, 16);
    bad[3] ^= 0x40;
    sc_aead_seal(&k, iv, a, an, buf, pn, tag);
    snprintf(what, sizeof(what), "%s: подменённый тег — SC_EAUTH", name);
    check(what, SC_EAUTH, sc_aead_open(&k, iv, a, an, buf, pn, bad));
    if (an) {
        sc_aead_seal(&k, iv, a, an, buf, pn, tag);
        a[0] ^= 1;
        snprintf(what, sizeof(what), "%s: подменённый AAD — SC_EAUTH", name);
        check(what, SC_EAUTH, sc_aead_open(&k, iv, a, an, buf, pn, tag));
    }
    sc_aead_free(&k);
}

static void test_aead(void) {
    aead_case("AES-128-GCM #2", SC_AES128_GCM, "00000000000000000000000000000000", "000000000000000000000000",
              "00000000000000000000000000000000", "", "0388dace60b6a392f328c2b971b2fe78",
              "ab6e47d42cec13bdf53a67b21257bddf");
    aead_case("AES-128-GCM #4", SC_AES128_GCM, "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
              "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
              "b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
              "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05"
              "1ba30b396a0aac973d58e091", "5bc94fbc3221a5db94fae95ae7121a47");
    aead_case("AES-256-GCM #14", SC_AES256_GCM,
              "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000",
              "00000000000000000000000000000000", "", "cea7403d4d606b6e074ec5d3baf39d18",
              "d0d1c8a799996bf0265b98b5d48ab919");
    aead_case("AES-256-GCM #16", SC_AES256_GCM,
              "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
              "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
              "b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
              "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838"
              "c5f61e6393ba7a0abcc9f662", "76fc6ece0f4e1768cddf8853bb2d551b");
    /* RFC 8439 §2.8.2: «Ladies and Gentlemen of the class of '99…». */
    aead_case("ChaCha20-Poly1305 RFC 8439", SC_CHACHA20_POLY1305,
              "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "070000004041424344454647",
              "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920"
              "636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c207375"
              "6e73637265656e20776f756c642062652069742e", "50515253c0c1c2c3c4c5c6c7",
              "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b"
              "1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
              "3ff4def08e4b7a9de576d26586cec64b6116", "1ae10b594f09e26a7e902ecbd0600691");

    /* На месте и на размерах записи TLS, с тегом СРАЗУ ЗА шифротекстом в том же буфере — так
     * лежит запись в tls13.c. 16401 — граница, на которой в прошлом не сходился тег. */
    static const size_t sizes[] = { 0, 1, 15, 16, 17, 300, 1439, 4096, 8203, 16384, 16401 };
    static const enum sc_aead_alg algs[] = { SC_AES128_GCM, SC_AES256_GCM, SC_CHACHA20_POLY1305 };
    static const char *names[] = { "AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305" };
    static unsigned char buf[16401 + 16], orig[16401];
    for (size_t a = 0; a < 3; a++) {
        unsigned char key[32], nonce[12], aad[5] = { 0x17, 0x03, 0x03, 0, 0 };
        for (int i = 0; i < 32; i++) key[i] = (unsigned char)(0xA5 ^ i);
        for (int i = 0; i < 12; i++) nonce[i] = (unsigned char)(0x5A + i);
        struct sc_aead k;
        sc_aead_setkey(&k, algs[a], key);
        int ok = 1;
        for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
            size_t n = sizes[s];
            for (size_t i = 0; i < n; i++) orig[i] = buf[i] = (unsigned char)(i * 31 + 7);
            nonce[11] = (unsigned char)s;
            if (sc_aead_seal(&k, nonce, aad, 5, buf, n, buf + n) != 0) ok = 0;
            unsigned char tag[16];
            memcpy(tag, buf + n, 16);
            if (sc_aead_open(&k, nonce, aad, 5, buf, n, tag) != 0) ok = 0;
            if (n && memcmp(buf, orig, n) != 0) ok = 0;
            if (memcmp(buf + n, tag, 16) != 0) ok = 0;     /* тег расшифровка не трогает */
        }
        char what[80];
        snprintf(what, sizeof(what), "%s: на месте на размерах записи TLS до 16401", names[a]);
        check(what, 1, ok);
        sc_aead_free(&k);
    }
    struct sc_aead none = { 0 };
    unsigned char n12[12] = { 0 }, t16[16];
    check("AEAD без ключа — SC_EINVAL", SC_EINVAL, sc_aead_seal(&none, n12, NULL, 0, t16, 0, t16));
}

/* ---- AES-256-CTR ----------------------------------------------------------------------------- */

static void test_aesctr(void) {
    unsigned char key[32], iv[16], p[64], buf[64], part[64];
    unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key, 32);
    unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", iv, 16);
    unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
          "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", p, 64);
    const char *c = "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
                    "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6";
    struct sc_aesctr x;
    check("AES-256-CTR: ключ", 0, sc_aesctr_init(&x, key, iv));
    check("AES-256-CTR: шифрование", 0, sc_aesctr_xor(&x, p, buf, 64));
    check_bytes("AES-256-CTR SP 800-38A F.5.5", c, buf, 64);
    sc_aesctr_free(&x);

    /* Кусками 1, 15, 17, 31: позиция внутри блока переживает вызов — так шифрует мост tgws,
     * отдавая поток порциями той длины, что пришла из сокета. */
    sc_aesctr_init(&x, key, iv);
    static const size_t cuts[] = { 1, 15, 17, 31 };
    size_t off = 0;
    for (size_t i = 0; i < 4; i++) { sc_aesctr_xor(&x, p + off, part + off, cuts[i]); off += cuts[i]; }
    check_bytes("AES-256-CTR кусками = целиком", c, part, 64);
    sc_aesctr_free(&x);

    sc_aesctr_init(&x, key, iv);
    sc_aesctr_xor(&x, buf, buf, 64);                    /* на месте, обратно */
    check_mem("AES-256-CTR: та же гамма расшифровывает", p, buf, 64);
    sc_aesctr_free(&x);

    /* Перенос счётчика через все 128 бит: MTProto считает блок как одно число big-endian. */
    unsigned char ivmax[16], z[32] = { 0 }, g[32], blk0[16], blk1[16];
    memset(ivmax, 0xff, 16);
    sc_aesctr_init(&x, key, ivmax);
    sc_aesctr_xor(&x, z, g, 32);
    sc_aesctr_free(&x);
    unsigned char zero_iv[16] = { 0 };
    sc_aesctr_init(&x, key, ivmax);
    sc_aesctr_xor(&x, z, blk0, 16);
    sc_aesctr_free(&x);
    sc_aesctr_init(&x, key, zero_iv);
    sc_aesctr_xor(&x, z, blk1, 16);
    sc_aesctr_free(&x);
    check_mem("AES-256-CTR: блок после ff..ff — это счётчик 00..00 (первый)", blk0, g, 16);
    check_mem("AES-256-CTR: блок после ff..ff — это счётчик 00..00 (второй)", blk1, g + 16, 16);
}

/* ---- X25519 ---------------------------------------------------------------------------------- */

#include "scrypto-pq.h"

/* ML-KEM-768: ключ из seed совпадает с Go, шифротекст Go декапсулируется в тот же секрет, своя
 * инкапсуляция сходится со своей декапсуляцией; испорченный ключ отвергается. */
static void test_mlkem(void) {
    unsigned char ek[SC_MLKEM768_EK], dk[SC_MLKEM768_DK], ss[32], ct[SC_MLKEM768_CT], ss2[32];
    check("ML-KEM: keygen", 0, sc_mlkem768_keygen(ek, dk, KEM_SEED));
    check("ML-KEM: ek совпал с Go", 0, memcmp(ek, KEM_EK, sizeof ek));
    check("ML-KEM: ek проходит проверку", 0, sc_mlkem768_ek_check(ek));
    check("ML-KEM: decaps шифротекста Go", 0, sc_mlkem768_decaps(ss, dk, KEM_CT));
    check("ML-KEM: секрет совпал с Go", 0, memcmp(ss, KEM_SS, 32));
    unsigned char rnd[32];
    for (int i = 0; i < 32; i++) rnd[i] = (unsigned char)(i * 5 + 1);
    check("ML-KEM: encaps", 0, sc_mlkem768_encaps(ct, ss, ek, rnd));
    check("ML-KEM: decaps своего шифротекста", 0, sc_mlkem768_decaps(ss2, dk, ct));
    check("ML-KEM: секреты сошлись", 0, memcmp(ss, ss2, 32));
    /* Неявный отказ: испорченный шифротекст даёт ДРУГОЙ секрет, а не ошибку. */
    ct[10] ^= 1;
    check("ML-KEM: испорченный ct — код 0", 0, sc_mlkem768_decaps(ss2, dk, ct));
    check("ML-KEM: испорченный ct — секрет другой", 1, memcmp(ss, ss2, 32) != 0);
    /* Коэффициент 0xFFF >= q = 3329: такой ключ Go не принимает (FIPS 203, 7.2). */
    unsigned char bad[SC_MLKEM768_EK];
    memcpy(bad, ek, sizeof bad);
    bad[0] = 0xFF; bad[1] |= 0x0F;
    check("ML-KEM: ключ с коэффициентом >= q — отказ", SC_EPARSE, sc_mlkem768_ek_check(bad));
    check("ML-KEM: encaps к такому ключу — отказ", SC_EPARSE, sc_mlkem768_encaps(ct, ss, bad, rnd));
}

/* ML-DSA-65: подпись circl проходит, любое искажение — нет. */
static void test_mldsa(void) {
    check("ML-DSA-65: подпись circl", 0, sc_mldsa65_verify(DSA_PK, DSA_MSG, sizeof DSA_MSG, DSA_SIG, sizeof DSA_SIG));
    unsigned char m[32], sg[SC_MLDSA65_SIG];
    memcpy(m, DSA_MSG, 32); m[0] ^= 1;
    check("ML-DSA-65: другое сообщение — SC_ESIG", SC_ESIG, sc_mldsa65_verify(DSA_PK, m, 32, DSA_SIG, sizeof DSA_SIG));
    memcpy(sg, DSA_SIG, sizeof sg); sg[100] ^= 1;
    check("ML-DSA-65: испорченная подпись — SC_ESIG", SC_ESIG, sc_mldsa65_verify(DSA_PK, DSA_MSG, 32, sg, sizeof sg));
    check("ML-DSA-65: короткая подпись — SC_ESIG", SC_ESIG, sc_mldsa65_verify(DSA_PK, DSA_MSG, 32, DSA_SIG, 100));
}

static void test_x25519(void) {
    unsigned char k[32], u[32], out[32];
    /* §5.2, первый вектор: скаляр НЕ прижат (a5 в младшем байте) — прижимает сама функция. */
    unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", k, 32);
    unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u, 32);
    check("X25519 RFC 7748 §5.2: код", 0, sc_x25519(out, k, u));
    check_bytes("X25519 RFC 7748 §5.2", "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", out, 32);

    /* §5.2, итерации: k = u = 9, затем k ← X25519(k, u), u ← старое k. */
    unsigned char kk[32] = { 9 }, uu[32] = { 9 }, t[32];
    for (int i = 1; i <= 1000; i++) {
        sc_x25519(t, kk, uu);
        memcpy(uu, kk, 32);
        memcpy(kk, t, 32);
        if (i == 1)
            check_bytes("X25519 RFC 7748: 1 итерация",
                        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", kk, 32);
    }
    check_bytes("X25519 RFC 7748: 1000 итераций",
                "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", kk, 32);

    /* §6.1: публичные половины из приватных и общий секрет с обеих сторон. */
    unsigned char ap[32], bp[32], apub[32], bpub[32], s1[32], s2[32];
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", ap, 32);
    unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bp, 32);
    sc_x25519_base(apub, ap);
    sc_x25519_base(bpub, bp);
    check_bytes("X25519 §6.1: открытый ключ Алисы", "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", apub, 32);
    check_bytes("X25519 §6.1: открытый ключ Боба", "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", bpub, 32);
    sc_x25519(s1, ap, bpub);
    sc_x25519(s2, bp, apub);
    check_bytes("X25519 §6.1: секрет у Алисы", "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", s1, 32);
    check_mem("X25519 §6.1: у Боба тот же", s1, s2, 32);

    /* Точка малого порядка (u = 0 и u = 1) даёт нулевой секрет — это отказ, а не ключ. */
    unsigned char zero[32] = { 0 }, one[32] = { 1 };
    check("X25519: u = 0 — отказ", SC_ECRYPTO, sc_x25519(out, ap, zero));
    check("X25519: u = 1 — отказ", SC_ECRYPTO, sc_x25519(out, ap, one));
}

/* ---- сертификаты ----------------------------------------------------------------------------- */

/* PEM → DER своим разбором: стенд не должен проверять библиотеку её же функцией. */
static size_t pem_der(const char *pem, unsigned char *out, size_t cap) {
    static const char *A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char *p = strstr(pem, "-----\n");
    if (!p) return 0;
    p += 6;
    unsigned acc = 0;
    int bits = 0;
    size_t n = 0;
    for (; *p && *p != '-'; p++) {
        const char *q = strchr(A, *p);
        if (!q || !*p) continue;
        acc = (acc << 6) | (unsigned)(q - A);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= cap) return 0;
            out[n++] = (unsigned char)(acc >> bits);
        }
    }
    return n;
}

struct der { unsigned char b[2048]; size_t n; };
static struct der D_LEAF, D_INTER, D_RSALEAF, D_P384, D_FAKECA, D_FAKELEAF, D_EXPIRED;

static struct sc_roots *roots_of(const char *pem) {
    struct sc_roots *r = NULL;
    return sc_roots_load(&r, (const unsigned char *)pem, strlen(pem)) == 0 ? r : NULL;
}

static int chain(struct sc_roots *r, const char *host, int n, ...) {
    const unsigned char *d[8];
    size_t dn[8];
    va_list ap;
    va_start(ap, n);
    for (int i = 0; i < n; i++) { struct der *x = va_arg(ap, struct der *); d[i] = x->b; dn[i] = x->n; }
    va_end(ap);
    return sc_chain_verify(r, d, dn, (size_t)n, host);
}

static void test_sig(void) {
    unsigned char d256[32], d384[48], sig[512];
    sc_hash(SC_SHA256, "steer scrypto", 13, d256);
    sc_hash(SC_SHA384, "steer scrypto", 13, d384);
    struct { const char *name, *hex; struct der *cert; enum sc_sig_alg alg; enum sc_hash h; } v[] = {
        { "ECDSA P-256 SHA-256",      SIG_ECDSA256,  &D_LEAF,    SC_SIG_ECDSA,     SC_SHA256 },
        { "ECDSA P-384 SHA-384",      SIG_ECDSA384,  &D_P384,    SC_SIG_ECDSA,     SC_SHA384 },
        { "RSA PKCS#1 v1.5 SHA-256",  SIG_PKCS1,     &D_RSALEAF, SC_SIG_RSA_PKCS1, SC_SHA256 },
        { "RSA-PSS SHA-256 соль 32",  SIG_PSS256,    &D_RSALEAF, SC_SIG_RSA_PSS,   SC_SHA256 },
        { "RSA-PSS SHA-384 соль 20",  SIG_PSS384S20, &D_RSALEAF, SC_SIG_RSA_PSS,   SC_SHA384 },
        { "RSA-PSS SHA-256 соль 0",   SIG_PSS256S0,  &D_RSALEAF, SC_SIG_RSA_PSS,   SC_SHA256 },
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        size_t sn = unhex(v[i].hex, sig, sizeof(sig));
        const unsigned char *dg = v[i].h == SC_SHA256 ? d256 : d384;
        size_t dn = sc_hash_len(v[i].h);
        char what[96];
        snprintf(what, sizeof(what), "подпись OpenSSL %s — верна", v[i].name);
        check(what, 0, sc_cert_verify_sig(v[i].cert->b, v[i].cert->n, v[i].alg, v[i].h, dg, dn, sig, sn));
        sig[sn / 2] ^= 0x10;
        snprintf(what, sizeof(what), "подпись %s с порчей — SC_ESIG", v[i].name);
        check(what, SC_ESIG, sc_cert_verify_sig(v[i].cert->b, v[i].cert->n, v[i].alg, v[i].h, dg, dn, sig, sn));
    }
    /* Не тот хеш и не тот способ — не «подходит похожее», а отказ. */
    size_t sn = unhex(SIG_PSS256, sig, sizeof(sig));
    check("PSS-подпись, проверенная как PKCS#1 v1.5, — SC_ESIG", SC_ESIG,
          sc_cert_verify_sig(D_RSALEAF.b, D_RSALEAF.n, SC_SIG_RSA_PKCS1, SC_SHA256, d256, 32, sig, sn));
    unsigned char wrong[32];
    memcpy(wrong, d256, 32);
    wrong[0] ^= 1;
    sn = unhex(SIG_ECDSA256, sig, sizeof(sig));
    check("ECDSA над другим дайджестом — SC_ESIG", SC_ESIG,
          sc_cert_verify_sig(D_LEAF.b, D_LEAF.n, SC_SIG_ECDSA, SC_SHA256, wrong, 32, sig, sn));
    check("ECDSA-подпись ключом RSA — отказ", 1,
          sc_cert_verify_sig(D_RSALEAF.b, D_RSALEAF.n, SC_SIG_ECDSA, SC_SHA256, d256, 32, sig, sn) != 0);
    check("длина дайджеста не та — SC_EINVAL", SC_EINVAL,
          sc_cert_verify_sig(D_LEAF.b, D_LEAF.n, SC_SIG_ECDSA, SC_SHA384, d256, 32, sig, sn));
}

struct worker { struct sc_roots *r; int bad; };

static void *verify_worker(void *arg) {
    struct worker *w = arg;
    for (int i = 0; i < 40; i++) {
        /* Чередование «хорошая цепочка — лист без промежуточного»: второй обязан отказать, даже
         * если в хранилище только что лежал временный промежуточный соседнего потока. */
        if (chain(w->r, "good.example", 2, &D_LEAF, &D_INTER) != 0) w->bad++;
        if (chain(w->r, "good.example", 1, &D_LEAF) != SC_ECHAIN) w->bad++;
        if (chain(w->r, "rsa.example", 3, &D_RSALEAF, &D_LEAF, &D_INTER) != 0) w->bad++;
    }
    return NULL;
}

static void test_chain(void) {
    struct sc_roots *r = roots_of(PEM_ROOT);
    check("хранилище корней загрузилось", 1, r != NULL);
    if (!r) return;
    check("лист + промежуточный, имя из SAN", 0, chain(r, "good.example", 2, &D_LEAF, &D_INTER));
    check("имя под шаблоном *.wild.example", 0, chain(r, "a.wild.example", 2, &D_LEAF, &D_INTER));
    check("шаблон не покрывает сам wild.example", SC_ECHAIN, chain(r, "wild.example", 2, &D_LEAF, &D_INTER));
    check("шаблон не покрывает два уровня", SC_ECHAIN, chain(r, "a.b.wild.example", 2, &D_LEAF, &D_INTER));
    check("адрес из SAN IP", 0, chain(r, "192.0.2.7", 2, &D_LEAF, &D_INTER));
    check("чужой адрес — отказ", SC_ECHAIN, chain(r, "192.0.2.8", 2, &D_LEAF, &D_INTER));
    check("чужое имя — отказ", SC_ECHAIN, chain(r, "bad.example", 2, &D_LEAF, &D_INTER));
    check("CN без SAN не подставляется за имя", SC_ECHAIN, chain(r, "leaf", 2, &D_LEAF, &D_INTER));
    check("без промежуточного — отказ", SC_ECHAIN, chain(r, "good.example", 1, &D_LEAF));
    check("лишний сертификат в цепочке не мешает", 0,
          chain(r, "good.example", 3, &D_LEAF, &D_RSALEAF, &D_INTER));
    check("после отказа временные промежуточные сняты", SC_ECHAIN, chain(r, "good.example", 1, &D_LEAF));
    check("лист прямо под корнем (P-384)", 0, chain(r, "p384.example", 1, &D_P384));
    check("промежуточный не CA — отказ", SC_ECHAIN,
          chain(r, "good.example", 3, &D_FAKELEAF, &D_FAKECA, &D_INTER));
    check("истёкший лист — отказ", SC_ECHAIN, chain(r, "good.example", 2, &D_EXPIRED, &D_INTER));

    /* Параллельные проверки: соединители туннеля проверяют цепочки из своих потоков. */
    pthread_t th[4];
    struct worker w[4];
    for (int i = 0; i < 4; i++) { w[i].r = r; w[i].bad = 0; pthread_create(&th[i], NULL, verify_worker, &w[i]); }
    int bad = 0;
    for (int i = 0; i < 4; i++) { pthread_join(th[i], NULL); bad += w[i].bad; }
    check("4 потока по 120 проверок: ни одного неверного ответа", 0, bad);
    sc_roots_free(r);

    r = roots_of(PEM_OTHER);
    check("чужой корень: цепочка не сходится", SC_ECHAIN, r ? chain(r, "good.example", 2, &D_LEAF, &D_INTER) : -99);
    sc_roots_free(r);

    /* Хранилище с мусором: запись, которая не разбирается, пропускается, остальные грузятся. */
    static char mixed[8192];
    snprintf(mixed, sizeof(mixed), "%s%s%s",
             "-----BEGIN CERTIFICATE-----\nAAAAAAAAAAAAAAAAAAAAAAAA\n-----END CERTIFICATE-----\n",
             PEM_OTHER, PEM_ROOT);
    r = roots_of(mixed);
    check("хранилище с испорченной записью: корень всё равно работает", 0,
          r ? chain(r, "good.example", 2, &D_LEAF, &D_INTER) : -99);
    sc_roots_free(r);
    r = roots_of("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    check("хранилище без единого корня — отказ загрузки", 1, r == NULL);
    sc_roots_free(r);
}

int main(void) {
    struct { const char *pem; struct der *d; } all[] = {
        { PEM_LEAF, &D_LEAF }, { PEM_INTER, &D_INTER }, { PEM_RSALEAF, &D_RSALEAF }, { PEM_P384, &D_P384 },
        { PEM_FAKECA, &D_FAKECA }, { PEM_FAKELEAF, &D_FAKELEAF }, { PEM_EXPIRED, &D_EXPIRED },
    };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        all[i].d->n = pem_der(all[i].pem, all[i].d->b, sizeof(all[i].d->b));

    test_hash();
    test_hmac();
    test_hkdf();
    test_aead();
    test_aesctr();
    test_x25519();
    test_mlkem();
    test_mldsa();
    test_sig();
    test_chain();
    return unit_done("scryptomatch");
}
