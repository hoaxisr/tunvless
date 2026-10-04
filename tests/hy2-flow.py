#!/usr/bin/env python3
"""Потоки для стенда hysteria2 (tests/run-hy2.sh): выгрузка на пределе.

Выгрузка в туннель быстрее, чем мультиплексор успевает шифровать и слать, — то, что curl с файлом
в 8 МиБ не показывает: sink (в пространстве сервера) принимает и считает принятое по секундам, send
(у клиента) льёт в туннель без остановки и без предела скорости. Проверяется, что приём идёт ровно:
не встаёт на нули и не проваливается (сверку делает оболочка стенда по журналу sink).

  hy2-flow.py sink --ip A --port P --log ФАЙЛ        принимает; раз в секунду «ВРЕМЯ БАЙТ» в журнал
  hy2-flow.py send --ip A --port P --secs T --conns N [--cc bbr]   льёт без остановки T секунд
"""
import argparse
import socket
import sys
import threading
import time

def listen(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(64)
    print("ready", flush=True)
    return s


def sink(a):
    srv = listen(a.ip, a.port)
    got = [0]
    live = [0]               # открытых соединений сейчас
    seen = [0]               # было ли хоть одно
    lock = threading.Lock()

    def report():
        # Журнал ведётся с первого принятого соединения и до закрытия последнего: пустые секунды ДО
        # и ПОСЛЕ выгрузки в него не попадают, а любая нулевая секунда посередине — это останов.
        t0 = time.time()
        last = 0
        with open(a.log, "w") as f:
            while True:
                time.sleep(1.0)
                cur = got[0]
                f.write(f"{int(time.time() - t0)} {cur - last}\n")
                f.flush()
                last = cur
                with lock:
                    if live[0] == 0:
                        return

    def rx(c):
        buf = bytearray(1 << 20)
        while True:
            try:
                n = c.recv_into(buf)
            except OSError:
                break
            if n == 0:
                break
            got[0] += n
        c.close()
        with lock:
            live[0] -= 1

    while True:
        c, _ = srv.accept()
        with lock:
            live[0] += 1
            first = not seen[0]
            seen[0] = 1
        if first:
            threading.Thread(target=report, daemon=True).start()
        threading.Thread(target=rx, args=(c,), daemon=True).start()


def send(a):
    stop = time.time() + a.secs
    total = [0]
    socks = []
    buf = b"\0" * (1 << 20)

    def tx(s):
        while time.time() < stop:
            try:
                s.sendall(buf)
                total[0] += len(buf)
            except OSError:
                break

    ths = []
    for _ in range(a.conns):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if a.cc:
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, a.cc.encode())
            except OSError:
                print(f"предупреждение: перегрузка {a.cc} недоступна — берётся умолчание ядра", file=sys.stderr)
        s.settimeout(30)
        s.connect((a.ip, a.port))
        s.settimeout(None)
        socks.append(s)
        th = threading.Thread(target=tx, args=(s,), daemon=True)
        th.start()
        ths.append(th)
    # Выгрузка, которая встала, держит sendall вечно: ждём не дольше срока и три секунды сверху,
    # потом обрываем сами. Здоровая кончается в срок, и закрытие идёт сразу — приёмнику не нужна
    # лишняя «пустая» секунда в конце журнала.
    for th in ths:
        th.join(max(0.0, stop + 3 - time.time()))
    for s in socks:
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        s.close()
    print(f"sent={total[0]}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["sink", "send"])
    ap.add_argument("--ip", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--secs", type=int, default=20)
    ap.add_argument("--conns", type=int, default=1)
    ap.add_argument("--log", default="/dev/null")
    ap.add_argument("--cc", default="")
    a = ap.parse_args()
    {"sink": sink, "send": send}[a.mode](a)


if __name__ == "__main__":
    main()
