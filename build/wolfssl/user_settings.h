/* wolfSSL build options for tunvless — the ONLY place they are written.
 *
 * Every wolfSSL .c sees this file (-DWOLFSSL_USER_SETTINGS), and so does the one tunvless file
 * that includes wolfSSL headers, src/lib/scrypto.c. That is a correctness condition, not taste:
 * the layout of wolfSSL structures (Aes, wc_Sha256, Hmac...) depends on these macros, and a
 * library built with one set next to a caller built with another corrupts memory silently. So
 * the options live nowhere else — not on command lines, not in configure.
 *
 * WHAT IS NEEDED. The TLS 1.3 and REALITY client is our own (src/proto/tls); wolfSSL provides
 * primitives only: SHA-256/384/512, HMAC, HKDF, AES-GCM, ChaCha20-Poly1305, AES-CTR (VLESS
 * encryption), X25519, ML-KEM-768 and ML-DSA-65 verification, and X.509 chain verification with
 * name and validity (RSA PKCS#1 v1.5 and PSS, ECDSA P-256/P-384 signatures). The chain is checked
 * by wolfSSL's X509 store, which is why part of its TLS layer (OPENSSL_EXTRA) is built.
 *
 * WHAT IS LEFT OUT ON PURPOSE: TLS 1.2 and older, a TLS server, QUIC, DH, DSA, DES, RC4, MD4,
 * PSK, PBKDF, the filesystem (certverify.c reads the roots itself, into a buffer) and socket I/O.
 *
 * SIZE. tunvless links wolfSSL statically with -ffunction-sections and --gc-sections, so what is
 * built but never called does not reach the binary.
 */
#ifndef STEER_WOLFSSL_USER_SETTINGS_H
#define STEER_WOLFSSL_USER_SETTINGS_H

/* ---- платформа ------------------------------------------------------------------------- */
/* Seed for the DRBG: os_rand_seed (src/lib/osrand.c) — getrandom(2) where the kernel has it,
 * /dev/urandom where it does not. WOLFSSL_GETRANDOM alone fails on the 3.4 kernels Entware's mips
 * and mipsel targets support (the call appeared in 3.17), and NO_FILESYSTEM below removes
 * wolfSSL's own fallback to /dev/urandom. */
#if !defined(__ASSEMBLER__)
extern int os_rand_seed(unsigned char *out, unsigned int n);
#endif
#define CUSTOM_RAND_GENERATE_SEED os_rand_seed
/* Byte order. configure sets WORDS_BIGENDIAN; with user settings nothing does, wolfSSL then assumes
 * little endian, and on big-endian MIPS (Entware mips-3.4) every hash, cipher and curve comes out
 * wrong — SHA-256("abc") included. Found by running the crypto tests under qemu-mips. */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_ORDER
#endif
#define NO_FILESYSTEM
#define WOLFSSL_USER_IO
/* Без сокетного ввода-вывода wolfio.h не подключает <sys/time.h>, а tls13.c wolfSSL на Linux
 * ждёт gettimeofday именно оттуда. Неявное объявление — ошибка у новых компиляторов
 * (-Werror=implicit-function-declaration), поэтому заголовок подключается здесь. Не для
 * ассемблера: этот файл видят и .S (через settings.h), а C-заголовок в них не разбирается. */
#if !defined(__ASSEMBLER__) && defined(__linux__)
#include <sys/time.h>
#endif
/* Потоки соединителей туннеля живут со скромным стеком (src/tunnel/tunnel.c), а разбор
 * сертификата и математика RSA держат на стеке килобайты. SMALL_STACK переносит крупные
 * временные буферы в кучу — медленнее на проценты там, где скорость не важна (рукопожатие), и
 * безопасно там, где переполнение стека молча портит соседний поток. */
#define WOLFSSL_SMALL_STACK
/* Файлы, которые wolfSSL включает в другие .c (ssl_*.c в ssl.c, misc.c как inline), собираются и
 * отдельно — пустыми; без этого ключа каждый такой файл предупреждает. */
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_ERROR_STRINGS
/* Reproducible build: no build date and time in the binary (OpenSSL_version string of the
 * compatibility layer). The OpenWrt and Entware wolfssl package does the same. */
#define HAVE_REPRODUCIBLE_BUILD

/* ---- TLS-стек wolfSSL: ровно то, что нужно хранилищу X509 ------------------------------ */
#define WOLFSSL_TLS13
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS
/* No TLS server in the shipped library. STEER_WOLFSSL_SERVER gives one to the tests that need a
 * TLS peer (tests/crypto-test.sh), as WOLFSSL_CERT_GEN gives them certificate issuing; tunvless
 * builds never set it. */
#ifndef STEER_WOLFSSL_SERVER
#define NO_WOLFSSL_SERVER
#endif
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_SNI
#define HAVE_ALPN
#define HAVE_EX_DATA
#define OPENSSL_EXTRA

/* ---- примитивы ------------------------------------------------------------------------- */
#define HAVE_HKDF
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
/* SHA-384/512 нужны рукопожатию (набор TLS_AES_256_GCM_SHA384, HMAC-SHA512 у REALITY, подписи в
 * сертификатах) — десяток вызовов на соединение, а развёрнутый цикл сжатия стоил 12 КБ флеша.
 * SHA-256 (им же считается транскрипт) остаётся быстрым. */
#define USE_SLOW_SHA512
#define HAVE_HASHDRBG

#define HAVE_AESGCM
/* Таблица GHASH на 4 бита (256 байт на ключ), а не на 8 (4 КБ): ключей в процессе столько же,
 * сколько направлений у соединений, и при 64 соединениях 8-битная таблица стоила бы полмегабайта
 * памяти. mbedtls, которую wolfSSL здесь сменила, держала ту же 4-битную. */
#define GCM_TABLE_4BIT
/* AES-CTR — the masking stream of VLESS encryption (src/proto/transport/trvenc.c). DIRECT is needed
 * for setting a key without a mode (wc_AesSetKeyDirect) and for encrypting one block. */
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define NO_AES_192
#define NO_AES_CBC
/* NO_AES_DECRYPT (без таблицы Td и обратного блока — GCM и CTR им не пользуются) здесь был бы
 * законен по смыслу, но в wolfSSL 5.9.4 он заодно снимает wc_AesGcmDecrypt — проверено сборкой.
 * Поэтому не задан. */

#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ONE_TIME_AUTH

#define HAVE_CURVE25519

#define HAVE_ECC
#define ECC_USER_CURVES
#undef  NO_ECC256
#define HAVE_ECC384
#define ECC_SHAMIR
#define ECC_TIMING_RESISTANT

/* ---- постквантовая часть (паритет с Xray-core) ------------------------------------------ */
/* ML-KEM-768 - половина гибрида X25519MLKEM768 в TLS 1.3 (ClientHello Chrome 131+, ответ
 * сервера REALITY) и обмен «mlkem768x25519plus» у VLESS encryption. ML-KEM-512 и -1024 не
 * нужны никому из тех, кого клиент встречает (Xray и Go используют ровно 768), и без них
 * снимается треть таблиц и кода.
 *
 * SHA-3 (SHAKE128/256, SHA3-256/512) - то, на чём стоит ML-KEM: матрица A разворачивается из seed
 * SHAKE128, шум - SHAKE256, хеши ключа и шифротекста - SHA3.
 *
 * ML-DSA-65 нужна ТОЛЬКО ДЛЯ ПРОВЕРКИ: REALITY кладёт подпись в расширение поддельного
 * сертификата, и клиент, у которого в узле задан mldsa65Verify (`pqv` в ссылке), обязан её
 * проверить. Подписывать и выпускать ключи мы не будем никогда, поэтому VERIFY_ONLY снимает
 * подпись, генерацию и разбор закрытого ключа; ASN.1-разбор не нужен (ключ приходит сырым 1952
 * байта). Экономящих память вариантов (SMALL_MEM) не берём: проверка редкая, но скорость не
 * режем ради килобайт (решение владельца: скорость важнее веса). */
/* ML-KEM — переносимым C, без ассемблера aarch64 (WOLFSSL_ARMASM у wolfSSL включает armv8-mlkem-asm, а тот
 * требует SQRDMLAH из ARMv8.1 (`rdm`): на Cortex-A53 роутеров и в базовой цели NDK его нет, ассемблер
 * отказывает в сборке). Скорость: рукопожатие делает по одному keygen и decaps на соединение, это доли
 * миллисекунды у x86 и единицы у слабых ядер; узким местом оно не бывает. */
#define WC_MLKEM_NO_ASM
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_NO_ML_KEM_512
#define WOLFSSL_NO_ML_KEM_1024
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define WOLFSSL_HAVE_MLDSA
#define WOLFSSL_WC_MLDSA
#define WOLFSSL_MLDSA_VERIFY_ONLY
#define WOLFSSL_MLDSA_NO_ASN1
#define WOLFSSL_NO_ML_DSA_44
#define WOLFSSL_NO_ML_DSA_87

#define WC_RSA_PSS
/* Соль PSS любой длины — как MBEDTLS_RSA_SALT_LEN_ANY прежде: RFC 8446 требует соль длиной с
 * хеш, но встречаются серверы (и переподписывающие посредники), у которых она другая, и
 * отвергать их значило бы объявить узел неисправным там, где подпись верна (certverify.c). */
#define WOLFSSL_PSS_SALT_LEN_DISCOVER
#define WOLFSSL_PSS_LONG_SALT
#define WC_RSA_BLINDING
#define TFM_TIMING_RESISTANT
#define WOLFSSL_SP_MATH_ALL
/* Математика больших чисел нужна только проверке цепочки у security=tls — несколько операций на
 * рукопожатие, — поэтому размер кода здесь важнее скорости. */
#define WOLFSSL_SP_SMALL

#define WOLFSSL_ASN_TEMPLATE
/* Имя в сертификате бывает и адресом (DoH на 1.1.1.1): без этих двух IP из SAN не разбирается,
 * и проверка имени отвергла бы честный сертификат. */
#define WOLFSSL_ALT_NAMES
#define WOLFSSL_IP_ALT_NAME

/* SHA-224 stays because the hash interface of src/lib/scrypto.h names it (as it names MD5 and
 * SHA-1); the VLESS path itself does not use them, and the linker drops what is not called. */
#define WOLFSSL_SHA224

#define NO_DSA
#define NO_DH
#define NO_RC4
#define NO_MD4
#define NO_DES3
#define NO_DES3_TLS_SUITES
#define NO_PSK
#define NO_PWDBASED

/* ---- ускорение по архитектуре ---------------------------------------------------------- */
/* x86_64: AES-NI, PCLMUL и AVX/AVX2 — только для AES и AES-GCM, ассемблером wolfSSL (файлы
 * aes_x86_64_asm.S и aes_gcm_asm.S), с выбором по CPUID во время работы: на процессоре без AES-NI
 * путь программный, и бинарник запускается там же, где запускался. Ключ ставит
 * build/wolfssl/build.sh вместе с файлами .S; без них сборка остаётся на переносимом C.
 *
 * Почему не USE_INTEL_SPEEDUP целиком (ассемблер ещё и для ChaCha20, Poly1305, SHA и X25519).
 * Замерено сборкой: он добавлял бинарнику x86_64 больше 540 КБ — ассемблер в один раздел, и
 * компоновщик не выбрасывает из него неиспользуемые ветки AVX-512 и VAES. На x86_64 шифр туннеля —
 * AES-GCM (reality.c выбирает его по AES-NI, как Chrome), поэтому ускоряется ровно он, а VAES и
 * AVX-512 (процессоры, которых в роутерах нет) сняты. */
#if defined(STEER_WOLFSSL_ASM) && defined(__x86_64__)
#define WOLFSSL_X86_64_BUILD
#define WOLFSSL_AESNI
#define USE_INTEL_SPEEDUP_FOR_AES
#define NO_VAES_SUPPORT
#define NO_AVX512_SUPPORT
#endif
/* aarch64: ARMv8 Crypto для AES, PMULL для GHASH, NEON для ChaCha20 и Poly1305, свой код X25519 и
 * SHA — встроенным ассемблером wolfSSL (файлы port/arm/armv8-*_c.c, то есть обычный C, который
 * собирает любой компилятор). Инструкции криптографии выбираются по getauxval(AT_HWCAP) во время
 * работы (wolfcrypt/src/cpuid.c, aes->use_aes_hw_crypto): на Cortex-A53 без расширения (Raspberry
 * Pi 4 и родня) AES идёт программно, а не падает с SIGILL. Прежде тот же путь давала mbedtls
 * (MBEDTLS_AESCE_C) — без него AES-GCM на роутерах aarch64 откатился бы к таблицам. Файлы вне
 * aarch64 собираются в пустоту, поэтому список у build.sh один на все цели. */
#if defined(__aarch64__) && !defined(STEER_WOLFSSL_NO_ARMASM)
#define WOLFSSL_ARMASM
#define WOLFSSL_ARMASM_INLINE
#endif

#endif
