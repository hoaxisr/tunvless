#!/bin/sh
# Выпустить тестовую PKI для tests/scryptomatch.c и напечатать tests/scrypto-pki.h.
#
#     sh tests/scrypto-pki.sh > tests/scrypto-pki.h
#
# Сертификаты и подписи выпускает OpenSSL, а проверяет их wolfSSL за слоем scrypto: так стенд
# ловит ошибку и в нашем вызове библиотеки, и в самой библиотеке, а не сверяет её с собой же.
# Ключи новые на каждый запуск — поэтому перевыпуск только целиком, скриптом, а не руками.
#
# Состав: корень (EC P-256) → промежуточный (RSA 2048, pathlen 0) → листья: EC P-256 с SAN
# good.example, *.wild.example и IP 192.0.2.7; RSA 2048 с SAN rsa.example (подписи PKCS#1 v1.5 и
# PSS с солью 32, 20 и 0); P-384 прямо под корнем; «поддельный CA» — лист без признака CA, которым
# подписан ещё один лист (цепочка через него обязана не сойтись); истёкший лист (2020-2021);
# посторонний корень. Срок остальных — 30 лет от выпуска.
set -eu
command -v openssl >/dev/null || { echo "нужен openssl" >&2; exit 2; }
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cd "$W"
printf '%s\n' '[req]' 'distinguished_name=dn' '[dn]' \
  '[ca]' 'basicConstraints=critical,CA:TRUE' 'keyUsage=critical,keyCertSign,cRLSign' 'subjectKeyIdentifier=hash' \
  '[inter]' 'basicConstraints=critical,CA:TRUE,pathlen:0' 'keyUsage=critical,keyCertSign,cRLSign' \
  'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' \
  '[leaf]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' \
  'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' \
  'subjectAltName=DNS:good.example,DNS:*.wild.example,IP:192.0.2.7' \
  '[rsaleaf]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
  'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' 'subjectAltName=DNS:rsa.example' \
  '[p384]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
  'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' 'subjectAltName=DNS:p384.example' \
  '[fakeca]' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
  'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' 'subjectAltName=DNS:fake.example' \
  '[fakeleaf]' 'basicConstraints=critical,CA:FALSE' 'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' \
  'subjectAltName=DNS:good.example' > ext.cnf
printf '%s\n' '[ca]' 'default_ca=d' '[d]' 'dir=.' 'database=./index.txt' 'new_certs_dir=./new' 'serial=./serial' \
  'default_md=sha256' 'policy=pol' 'copy_extensions=none' 'unique_subject=no' '[pol]' 'commonName=supplied' \
  '[expired]' 'basicConstraints=critical,CA:FALSE' 'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid' \
  'subjectAltName=DNS:good.example' > ca.cnf
D=10957
q() { "$@" >/dev/null 2>&1; }
q openssl ecparam -name prime256v1 -genkey -noout -out root.key
q openssl req -x509 -new -key root.key -sha256 -days $D -subj "/CN=steer test root" -extensions ca -config ext.cnf -out root.pem
q openssl ecparam -name prime256v1 -genkey -noout -out other.key
q openssl req -x509 -new -key other.key -sha256 -days $D -subj "/CN=steer other root" -extensions ca -config ext.cnf -out other.pem
q openssl genrsa -out inter.key 2048
q openssl req -new -key inter.key -subj "/CN=steer test intermediate" -config ext.cnf -out inter.csr
q openssl x509 -req -in inter.csr -CA root.pem -CAkey root.key -set_serial 2 -sha256 -days $D -extfile ext.cnf -extensions inter -out inter.pem
leaf() { # имя секция издатель серийный
    q openssl req -new -key "$1.key" -subj "/CN=$1" -config ext.cnf -out "$1.csr"
    q openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -set_serial "$4" -sha256 -days $D \
        -extfile ext.cnf -extensions "$2" -out "$1.pem"
}
q openssl ecparam -name prime256v1 -genkey -noout -out leaf.key;     leaf leaf leaf inter 10
q openssl genrsa -out rsaleaf.key 2048;                              leaf rsaleaf rsaleaf inter 11
q openssl ecparam -name secp384r1 -genkey -noout -out p384.key;      leaf p384 p384 root 12
q openssl ecparam -name prime256v1 -genkey -noout -out fakeca.key;   leaf fakeca fakeca inter 13
q openssl ecparam -name prime256v1 -genkey -noout -out fakeleaf.key; leaf fakeleaf fakeleaf fakeca 14
mkdir new
: > index.txt
echo 20 > serial
q openssl ecparam -name prime256v1 -genkey -noout -out expired.key
q openssl req -new -key expired.key -subj "/CN=expired" -config ext.cnf -out expired.csr
q openssl ca -batch -config ca.cnf -cert inter.pem -keyfile inter.key -in expired.csr -out expired.pem \
    -startdate 20200101000000Z -enddate 20210101000000Z -extensions expired -notext
printf 'steer scrypto' > msg
q openssl dgst -sha256 -sign leaf.key -out s.ecdsa256 msg
q openssl dgst -sha384 -sign p384.key -out s.ecdsa384 msg
q openssl dgst -sha256 -sign rsaleaf.key -out s.pkcs1 msg
q openssl dgst -sha256 -sign rsaleaf.key -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -out s.pss256 msg
q openssl dgst -sha384 -sign rsaleaf.key -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20 -out s.pss384s20 msg
q openssl dgst -sha256 -sign rsaleaf.key -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:0 -out s.pss256s0 msg

echo "/* Тестовая PKI для tests/scryptomatch.c. СГЕНЕРИРОВАН: sh tests/scrypto-pki.sh > tests/scrypto-pki.h"
echo " * ($(openssl version | cut -d' ' -f1-2), $(date -u +%Y-%m-%d)). Руками не править — только перевыпуск целиком. */"
echo "#ifndef STEER_TESTS_SCRYPTO_PKI_H"
echo "#define STEER_TESTS_SCRYPTO_PKI_H"
for c in root inter leaf rsaleaf p384 fakeca fakeleaf expired other; do
    echo "static const char PEM_$(echo $c | tr a-z A-Z)[] ="
    sed 's/.*/    "&\\n"/' $c.pem
    echo "    ;"
done
for s in ecdsa256 ecdsa384 pkcs1 pss256 pss384s20 pss256s0; do
    echo "static const char SIG_$(echo $s | tr a-z A-Z)[] ="
    od -An -v -tx1 s.$s | tr -d ' \n' | fold -w 60 | sed 's/.*/    "&"/'
    echo
    echo "    ;"
done
echo "#endif"
