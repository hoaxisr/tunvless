#!/usr/bin/env python3
"""Сервер DoH по HTTP/2 для проверки клиента dnsd: настоящие кадры по TLS (ALPN h2), поведение — по пути.

Зачем свой, если есть dnsproxy (tests/doqup.sh). dnsproxy — независимая реализация и отвечает всегда
правильно, а клиенту важны как раз неправильные и редкие случаи: отказ кодом 505, сброс потока,
GOAWAY посреди работы, малый предел потоков. Их удобно вызывать по пути запроса. Сервер не разбирает
HPACK целиком: клиент шлёт только индексы статической таблицы и литералы без индексации и без Хаффмана,
чего для чтения :path хватает.

    doh2-server.py АДРЕС ПОРТ СЕРТИФИКАТ КЛЮЧ ЖУРНАЛ

Пути:
  /ok        ответ 200 на каждый вопрос (одна запись A, 203.0.113.99)
  /st505     ответ 505 с телом; /st505h — то же, код записан кодом Хаффмана (как у Quad9)
  /rst       на каждый вопрос RST_STREAM REFUSED_STREAM
  /goaway    после первого ответа на соединении — GOAWAY(NO_ERROR, last = этот поток); на новом — снова
  /max2      SETTINGS_MAX_CONCURRENT_STREAMS = 2, ответ через 0,3 с; в журнал — наибольшее число потоков разом
  /silent    вопрос принимается, ответа нет
  /split     заголовки ответа двумя кадрами (HEADERS + CONTINUATION), тело двумя DATA

Ключ --h1: сервер знает один HTTP/1.1 (ALPN http/1.1, как Quad9 наоборот — сервер стенда dnsup): на
/st505 отвечает 505, на остальные пути — 200; ответ Content-Length, соединение keep-alive.

Журнал (по строке): «conn N», «req ПУТЬ sid=S», «maxconc K», «ping-ack», «settings-ack».
"""
import socket, ssl, struct, sys, threading, time

addr, port, crt, key, logf = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
lg = open(logf, "a", buffering=1)
lock = threading.Lock()
nconn = 0


def log(s):
    with lock:
        lg.write(s + "\n")


def frame(t, fl, sid, body=b""):
    return struct.pack(">I", len(body))[1:] + bytes([t, fl]) + struct.pack(">I", sid) + body


def answer(q):
    e = 12
    while q[e]:
        e += 1 + q[e]
    e += 5
    return (q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x01\x00\x00\x00\x00" + q[12:e] +
            b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([203, 0, 113, 99]))


def hpath(blk):
    i, path = 0, None
    while i < len(blk):
        b = blk[i]
        if b & 0x80:
            i += 1
            continue
        idx = b & 0x0F
        i += 1
        if idx == 0:
            ln = blk[i]; i += 1 + ln
        ln = blk[i]; i += 1
        if idx == 4:
            path = blk[i:i + ln].decode()
        i += ln
    return path


def serve_h1(c, n):
    buf = b""
    while True:
        while b"\r\n\r\n" not in buf:
            d = c.recv(4096)
            if not d:
                return
            buf += d
        head, _, buf = buf.partition(b"\r\n\r\n")
        path = head.split(b" ")[1].decode()
        cl = 0
        for ln in head.split(b"\r\n")[1:]:
            if ln.lower().startswith(b"content-length:"):
                cl = int(ln.split(b":")[1])
        while len(buf) < cl:
            buf += c.recv(4096)
        q, buf = buf[:cl], buf[cl:]
        log("req %s h1" % path)
        if path == "/st505":
            m = b"requires HTTP/2 in accordance with section 5.2 of RFC 8484"
            c.sendall(b"HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: %d\r\n\r\n" % len(m) + m)
        else:
            a = answer(q)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: %d\r\n\r\n" % len(a) + a)


def serve(c, n):
    if H1:
        return serve_h1(c, n)
    def send(b):
        with lock:
            c.sendall(b)
    buf = b""
    while len(buf) < 24:
        d = c.recv(4096)
        if not d:
            return
        buf += d
    buf = buf[24:]
    streams = {}          # sid -> [path, body]
    active = [0, 0]       # сейчас, наибольшее
    answered = 0

    def respond(sid, path, q):
        nonlocal answered
        if path == "/silent" or (path == "/goaway" and answered >= 1):
            return                                   # после GOAWAY остальные потоки сервер не обрабатывает
        if path == "/rst":
            send(frame(3, 0, sid, struct.pack(">I", 7)))
            return
        if path in ("/st505", "/st505h"):
            v = b"\x08\x83\x6c\x0d\xff" if path.endswith("h") else b"\x08\x03505"
            send(frame(1, 4, sid, v) + frame(0, 1, sid, b"requires HTTP/2 in accordance with section 5.2 of RFC 8484"))
            return
        if path == "/max2":
            active[0] += 1
            active[1] = max(active[1], active[0])
            log("maxconc %d" % active[1])
            time.sleep(0.3)
            active[0] -= 1
        a = answer(q)
        if path == "/split":
            send(frame(1, 0, sid, b"\x88") + frame(9, 4, sid, b"\x0f\x10\x17application/dns-message"))
            send(frame(0, 0, sid, a[:20]) + frame(0, 1, sid, a[20:]))
        else:
            send(frame(1, 4, sid, b"\x88\x0f\x10\x17application/dns-message") + frame(0, 1, sid, a))
        answered += 1
        if path == "/goaway" and answered == 1:
            send(frame(7, 0, 0, struct.pack(">II", sid, 0)))

    # Предел потоков объявляется до первого запроса, поэтому он задаётся ключом --max при запуске, а не
    # путём (для /max2 стенд запускает второй экземпляр с --max 2).
    send(frame(4, 0, 0, struct.pack(">HI", 3, MAXS)) + frame(6, 0, 0, b"pingpong"))
    while True:
        while len(buf) >= 9:
            ln = int.from_bytes(buf[:3], "big")
            if len(buf) < 9 + ln:
                break
            t, fl = buf[3], buf[4]
            sid = struct.unpack(">I", buf[5:9])[0] & 0x7FFFFFFF
            body = buf[9:9 + ln]
            buf = buf[9 + ln:]
            if t == 4 and fl & 1:
                log("settings-ack")
            elif t == 4:
                send(frame(4, 1, 0))
            elif t == 6 and fl & 1:
                log("ping-ack")
            elif t == 1:
                streams[sid] = [hpath(body), b""]
                log("req %s sid=%d" % (streams[sid][0], sid))
            elif t == 0:
                streams[sid][1] += body
                if fl & 1:
                    p, q = streams.pop(sid)
                    threading.Thread(target=respond, args=(sid, p, q), daemon=True).start()
        d = c.recv(65536)
        if not d:
            return
        buf += d


MAXS = 100
H1 = "--h1" in sys.argv
if "--max" in sys.argv:
    MAXS = int(sys.argv[sys.argv.index("--max") + 1])

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(crt, key)
ctx.set_alpn_protocols(["http/1.1"] if H1 else ["h2"])
ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind((addr, port))
ls.listen(64)
while True:
    raw, _ = ls.accept()
    try:
        c = ctx.wrap_socket(raw, server_side=True)
    except Exception:
        continue
    nconn += 1
    log("conn %d" % nconn)
    threading.Thread(target=serve, args=(c, nconn), daemon=True).start()
