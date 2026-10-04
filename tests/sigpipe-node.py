#!/usr/bin/env python3
"""Поддельный узел VLESS для стенда tests/sigpipe.sh: закрывает соединения так, как закрывает их
настоящий сервер под нагрузкой, — раньше, чем клиент закончил писать.

Нужен ровно один случай. Клиент туннеля (steer-vless) переносит в узел байты клиента локальной сети
по мере их прихода из TUN. Узел закрывает соединение — а в очереди TUN у клиента ещё лежат пакеты,
которые стек дописывает в уже закрытый сокет. Закрытие на стороне узла идёт в два шага: FIN, затем RST
на каждый следующий сегмент (закрытый сокет с непрочитанным входом отвечает сбросом). Запись в сокет,
получивший и то и другое, — EPIPE, а без выключенного SIGPIPE — смерть процесса (cli/modcmd.c). Настоящий
узел (Xray в измерении, где это нашли) делает то же самое, когда сервер по ту сторону — iperf3 — закрывает
потоки в конце испытания.

Что узел делает с соединением, решает порт назначения, который клиент назвал в заголовке VLESS (сам адрес
разбирается и выбрасывается, как у tests/fake-vless.py):

    7    эхо строки: ответ VLESS, затем читает строку до \\n, отвечает «PONG <строка>» и закрывает штатно —
         проверка, что туннель жив;
    80   приёмник, который закрывается рано: ответ VLESS, дочитывает случайное число байт из диапазона
         --early-min..--early-max и закрывается так, как описано выше (shutdown(WR), затем close с
         непрочитанным входом — FIN и сразу RST);
    81   источник: ответ VLESS и поток данных, пока клиент не уйдёт;
    82   приёмник, который не закрывается: читает до конца потока.

security=none и security=tls (TLS 1.3 средствами ssl; сертификат стенда самоподписанный, клиент ходит с
insecure: true). Счётчики по портам печатаются в stderr раз в секунду и по завершении — так стенд видит, что
нагрузка дошла до узла.
"""
import argparse
import os
import socket
import ssl
import sys
import threading
import time

ADDR_IPV4, ADDR_DOMAIN, ADDR_IPV6 = 1, 2, 3

counters = {}
clock = threading.Lock()


def bump(key, n=1):
    with clock:
        counters[key] = counters.get(key, 0) + n


def recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_request(sock):
    """Заголовок VLESS: версия, UUID, длина допов, допы, команда, порт, тип и тело адреса.
    Возвращает (uuid, команда, порт) или None."""
    head = recv_exactly(sock, 18)
    if not head or head[0] != 0:
        return None
    uuid, addon_n = head[1:17], head[17]
    if addon_n and recv_exactly(sock, addon_n) is None:
        return None
    tail = recv_exactly(sock, 4)
    if not tail:
        return None
    cmd, port, atype = tail[0], (tail[1] << 8) | tail[2], tail[3]
    if atype == ADDR_IPV4:
        need = 4
    elif atype == ADDR_IPV6:
        need = 16
    elif atype == ADDR_DOMAIN:
        ln = recv_exactly(sock, 1)
        if not ln:
            return None
        need = ln[0]
    else:
        return None
    if recv_exactly(sock, need) is None:
        return None
    return uuid, cmd, port


def close_like_a_busy_server(sock):
    """FIN, а следом RST: shutdown(WR) отправляет FIN, close с непрочитанным входом — сброс. Клиент
    сначала видит конец потока (CLOSE_WAIT), а следующий же сегмент своей записи получает RST и,
    записав ещё раз, — EPIPE."""
    try:
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class Node:
    def __init__(self, a):
        self.uuid = bytes.fromhex(a.uuid.replace("-", ""))
        self.early_min, self.early_max = a.early_min, a.early_max
        self.ctx = None
        if a.tls:
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            self.ctx.load_cert_chain(a.tls[0], a.tls[1])
        self.rand = os.urandom

    def serve(self, raw):
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock = raw
        try:
            if self.ctx:
                raw.settimeout(10)
                sock = self.ctx.wrap_socket(raw, server_side=True)
            sock.settimeout(30)
            req = read_request(sock)
            if req is None or req[0] != self.uuid:
                bump("отказ")
                return
            _, _, port = req
            sock.sendall(b"\x00\x00")
            if port == 7:
                buf = b""
                while not buf.endswith(b"\n"):
                    c = sock.recv(4096)
                    if not c:
                        return
                    buf += c
                sock.sendall(b"PONG " + buf)
                bump("эхо")
                time.sleep(0.2)
            elif port == 80:
                span = self.early_max - self.early_min
                want = self.early_min + int.from_bytes(self.rand(4), "big") % max(span, 1)
                got = 0
                while got < want:
                    c = sock.recv(min(262144, want - got))
                    if not c:
                        bump("клиент закрыл раньше")
                        return
                    got += len(c)
                bump("рано закрыто")
                bump("байт принято", got)
                close_like_a_busy_server(sock)
                sock = None
            elif port == 81:
                chunk = b"\x5a" * 65536
                sent = 0
                try:
                    while True:
                        sock.sendall(chunk)
                        sent += len(chunk)
                except OSError:
                    bump("источник: клиент ушёл")
                bump("байт отдано", sent)
            elif port == 82:
                got = 0
                while True:
                    c = sock.recv(262144)
                    if not c:
                        break
                    got += len(c)
                bump("приёмник дочитан")
                bump("байт принято", got)
        except (OSError, ssl.SSLError):
            bump("обрыв")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--uuid", required=True)
    ap.add_argument("--tls", nargs=2, metavar=("СЕРТИФИКАТ", "КЛЮЧ"))
    ap.add_argument("--early-min", type=int, default=64 * 1024)
    ap.add_argument("--early-max", type=int, default=1024 * 1024)
    a = ap.parse_args()
    node = Node(a)
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((a.bind, a.port))
    ls.listen(512)
    print("ready", flush=True)

    def report():
        while True:
            time.sleep(1)
            with clock:
                line = " ".join("%s=%d" % kv for kv in sorted(counters.items()))
            print("узел:", line, file=sys.stderr, flush=True)
    threading.Thread(target=report, daemon=True).start()
    while True:
        c, _ = ls.accept()
        threading.Thread(target=node.serve, args=(c,), daemon=True).start()


main()
