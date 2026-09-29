#!/usr/bin/env python3
"""Сервер DNS для стенда апстримов резолвера (tests/dnsup.sh): один адрес, все транспорты.

    dnsup-server.py АДРЕС ЖУРНАЛ СЕРТИФИКАТ КЛЮЧ [--zone СУФФИКС=IP ...] [--chunked] [--h2only]

Слушает на АДРЕС: UDP и TCP на 53, DoT (TLS) на 853, DoH (HTTPS, HTTP/1.1, keep-alive) на 443 и
на 8443. На имя под суффиксом зоны отвечает A-записью; имя, которого нет в зонах, — NXDOMAIN.
Адрес ответа для имени — из файла ЖУРНАЛ.zone.<суффикс>, если он есть (переезд домена между
запросами), иначе тот, что дан в --zone. Каждый принятый вопрос дописывается в ЖУРНАЛ строкой
`протокол адрес-клиента имя`: по адресу клиента стенд видит, каким путём вопрос пришёл (у роутера
их два — с WAN и с туннеля), а по протоколу — какой транспорт. Ответы DoH уходят с
Content-Length, а с --chunked — кусками (Transfer-Encoding: chunked). С --h2only DoH согласует
только h2, то есть клиент, умеющий одно HTTP/1.1, обязан получить отказ рукопожатия.

Зависит только от стандартной библиотеки: разбор и сборка сообщений DNS — здесь же.
"""
import os
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time

ADDR, LOG, CERT, KEY = sys.argv[1:5]
ZONES = {}
CHUNKED = "--chunked" in sys.argv
H2ONLY = "--h2only" in sys.argv
TTL = 60
for i, a in enumerate(sys.argv):
    if a == "--zone":
        k, v = sys.argv[i + 1].split("=")
        ZONES[k] = v
    if a == "--ttl":
        TTL = int(sys.argv[i + 1])

lock = threading.Lock()


def log(proto, client, name):
    with lock:
        with open(LOG, "a") as f:
            f.write("%s %s %s\n" % (proto, client, name))


def parse_q(data):
    if len(data) < 12:
        return None
    pos = 12
    labels = []
    while True:
        if pos >= len(data):
            return None
        l = data[pos]
        if l == 0:
            pos += 1
            break
        labels.append(data[pos + 1:pos + 1 + l].decode("ascii", "replace"))
        pos += 1 + l
    qtype, qclass = struct.unpack(">HH", data[pos:pos + 4])
    return ".".join(labels).lower(), qtype, qclass, pos + 4


def answer(data, proto, client):
    q = parse_q(data)
    if not q:
        return None
    name, qtype, qclass, qend = q
    log(proto, client, name)
    ip = None
    for suf, v in ZONES.items():
        if name == suf or name.endswith("." + suf):
            zf = "%s.zone.%s" % (LOG, suf)
            if os.path.exists(zf):
                v = open(zf).read().strip()
            ip = v
            break
    flags = 0x8180 | (data[2] & 0x01) << 8
    if ip is None:
        return data[:2] + struct.pack(">HHHHH", 0x8183, 1, 0, 0, 0) + data[12:qend]
    if qtype != 1:
        return data[:2] + struct.pack(">HHHHH", flags, 1, 0, 0, 0) + data[12:qend]
    rr = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, TTL, 4) + socket.inet_aton(ip)
    return data[:2] + struct.pack(">HHHHH", flags, 1, 1, 0, 0) + data[12:qend] + rr


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        r = answer(data, "udp", self.client_address[0])
        if r:
            sock.sendto(r, self.client_address)


def read_exact(f, n):
    b = b""
    while len(b) < n:
        c = f.recv(n - len(b))
        if not c:
            return None
        b += c
    return b


class Stream(socketserver.BaseRequestHandler):
    proto = "tcp"

    def handle(self):
        s = self.request
        s.settimeout(30)
        try:
            while True:
                h = read_exact(s, 2)
                if not h:
                    return
                data = read_exact(s, struct.unpack(">H", h)[0])
                if data is None:
                    return
                r = answer(data, self.proto, self.client_address[0])
                if r:
                    s.sendall(struct.pack(">H", len(r)) + r)
        except (OSError, ssl.SSLError):
            return


class DoT(Stream):
    proto = "dot"


class DoH(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        s.settimeout(30)
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    c = s.recv(4096)
                    if not c:
                        return
                    buf += c
                head, buf = buf.split(b"\r\n\r\n", 1)
                lines = head.decode("latin1").split("\r\n")
                method, path, _ = lines[0].split(" ", 2)
                hd = {}
                for ln in lines[1:]:
                    k, _, v = ln.partition(":")
                    hd[k.strip().lower()] = v.strip()
                n = int(hd.get("content-length", "0"))
                while len(buf) < n:
                    c = s.recv(4096)
                    if not c:
                        return
                    buf += c
                body, buf = buf[:n], buf[n:]
                if method == "GET" and "dns=" in path:
                    import base64
                    b64 = path.split("dns=", 1)[1].split("&")[0]
                    body = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
                elif method != "POST" or not path.startswith("/dns-query"):
                    s.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                    continue
                r = answer(body, "doh", self.client_address[0])
                if not r:
                    s.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                    continue
                hdr = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                if CHUNKED:
                    h1 = r[:7]
                    h2 = r[7:]
                    s.sendall(hdr + b"Transfer-Encoding: chunked\r\n\r\n" +
                              b"%x\r\n" % len(h1) + h1 + b"\r\n" + b"%x\r\n" % len(h2) + h2 + b"\r\n0\r\n\r\n")
                else:
                    s.sendall(hdr + b"Content-Length: %d\r\n\r\n" % len(r) + r)
        except (OSError, ssl.SSLError, ValueError):
            return


class TCPS(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPS(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


def tls_ctx(alpn):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.minimum_version = ssl.TLSVersion.TLSv1_2
    c.load_cert_chain(CERT, KEY)
    if alpn:
        c.set_alpn_protocols(alpn)
    return c


class TLSTCPS(TCPS):
    ctx = None

    def get_request(self):
        sock, addr = super().get_request()
        try:
            # Рукопожатие — в потоке обработчика (при первом чтении), а не в потоке приёма.
            return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr
        except (ssl.SSLError, OSError):
            sock.close()
            raise


def serve(srv):
    threading.Thread(target=srv.serve_forever, daemon=True).start()


serve(UDPS((ADDR, 53), UDP))
serve(TCPS((ADDR, 53), Stream))
dot = TLSTCPS((ADDR, 853), DoT)
dot.ctx = tls_ctx(None)
serve(dot)
for port in (443, 8443):
    doh = TLSTCPS((ADDR, port), DoH)
    doh.ctx = tls_ctx(["h2"] if H2ONLY else ["http/1.1"])
    serve(doh)
print("ready", flush=True)
while True:
    time.sleep(3600)
