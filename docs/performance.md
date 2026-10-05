# Performance on a router

Measured 2026-10-05 on a Keenetic KN-1810 against a test Xray-core server, with sing-box in TUN
mode through the same nodes for comparison. The question was whether tunvless needs optimizing on
the routers it is made for.

**Short answer:** on this router tunvless carries the whole uplink (84 Mbit/s down, 40-44 up) with
one hardware thread busy, while sing-box tops out at 25-35 Mbit/s with all four threads busy. With
an uplink of up to ~90 Mbit/s no optimization is needed. The ceiling of tunvless here is about
90 Mbit/s down, set by its single loop thread; the download path, not the encryption, is where an
optimization would start (see [What limits tunvless](#what-limits-tunvless)).

## The setup

| | |
|---|---|
| Router | Keenetic KN-1810: MediaTek MT7621 (MIPS 1004Kc, 2 cores x 2 threads, 880 MHz), 256 MB RAM, Entware `mipsel-3.4`, kernel 4.9 |
| Uplink | 40-100 Mbit/s, 24 ms round trip to the server |
| Server | VPS, 1 vCPU, Debian 13, Xray-core 26.3.27 |
| tunvless | 0.1.0 at `d821ba7`, the `mipsel-3.4` package built by CI |
| sing-box | 1.14.2, the official `linux-mipsle-softfloat` release (go1.26.8) |

Nodes on the server, all to the same target:

- `vision`: REALITY, tcp, `xtls-rprx-vision`;
- `xhttp`: REALITY, xhttp (`auto`, so stream-one);
- `grpc`: REALITY, gRPC gun;
- `plain`: VLESS over tcp without security, to separate the cost of the encryption.

REALITY's `dest` was `dl.google.com:443`. With `www.microsoft.com:443` every REALITY handshake
failed ("handshake did not complete") for tunvless and for Xray's own client alike: the name
resolved to IPv6 Akamai addresses from that server. Not a client problem, but worth knowing when a
REALITY node will not come up.

The traffic is iperf3. The server's `freedom` outbound redirects every connection to an iperf3
server on its own loopback, so the server's internet link is not part of the measurement. On the
router only the test address (198.18.0.1) is routed into the tunnel; the router's own traffic and
the connection to the server are untouched. The router has no LAN machine behind it, so iperf3 runs
on the router itself.

Each run is 15 s (10 s for the last sing-box runs), measured with
[`tests/bench/measure.sh`](../tests/bench/measure.sh): the rate, the busy CPU of the whole router
(out of 400% for four threads) and the CPU of the client process (100% = one thread).

**One caveat about the CPU numbers.** iperf3 on the router is the receiver: the kernel runs its TCP
receive path inside the client's write to the TUN device, and that time counts towards the client
process. A router forwarding to a LAN host would spend it in softirq instead. The absolute numbers
are therefore somewhat high, for tunvless and sing-box alike, so the comparison stands.

## Results

### Four streams

The comparison that matters: one stream is bound by the 24 ms round trip for everyone.

| | down, Mbit/s | process CPU | up, Mbit/s | process CPU |
|---|---:|---:|---:|---:|
| no tunnel (the uplink) | 83.5 | — | 43.9 | — |
| **tunvless, vision** | **84.4** | **98%** | **40.1** | **54%** |
| tunvless, xhttp | 81.9 | 101% | 43.2 | 61% |
| tunvless, grpc | 83.5 | 101% | 43.3 | 62% |
| tunvless, plain | 84.0 | 90% | 43.3 | 24% |
| sing-box, vision, `system` stack | 34.5 | 332% | 35.8 | 336% |
| sing-box, vision, `gvisor` stack | 24.3 | 336% | 35.4 | 336% |
| sing-box, plain, `system` stack | 45.3 | 176% | 44.7 | 60% |
| sing-box, plain, `gvisor` stack | 69.2 | 256% | 44.7 | 90% |

### One stream

| | down, Mbit/s | process CPU | up, Mbit/s | process CPU |
|---|---:|---:|---:|---:|
| no tunnel | 40.8 | — | 43.5 | — |
| tunvless, vision | 40.5 | 65% | 40.7 | 50% |
| tunvless, xhttp | 40.3 | 68% | 43.8 | 59% |
| tunvless, grpc | 40.5 | 69% | 43.0 | 60% |
| tunvless, plain | 44.1 | 56% | 43.3 | 19% |
| sing-box, vision, `system` | 18.2 | 175% | 20.3 | 130% |
| sing-box, vision, `gvisor` | 14.4 | 186% | 18.6 | 136% |
| sing-box, plain, `system` | 44.9 | 146% | 38.4 | 42% |
| sing-box, plain, `gvisor` | 39.5 | 208% | 43.3 | 85% |

Without a tunnel the router itself spends 61% (one stream down) to 106% (four streams down) of its
400% on the network and iperf3.

### sing-box notes

- sing-box's `system` and `mixed` stacks take TCP through the kernel: the connection appears as a
  new incoming one on the TUN interface, and Keenetic's `INPUT` policy is `DROP`. Without a rule
  accepting the interface (`iptables -I INPUT -i <tun> -j ACCEPT`), nothing passes; the `gvisor`
  stack works without one. tunvless runs its own TCP and needs no such rule.
- A sing-box 1.14.2 built from source with only `with_gvisor,with_utls` (42 MB instead of 84) was
  about half as fast as the official build with REALITY (16-20 Mbit/s). The tables use the official
  build. It needs about 34 MB of RAM running, and its 84 MB binary in `/tmp` is RAM too: on a
  256 MB router that leaves little room.

## What the numbers say

1. **tunvless is not the bottleneck here; the uplink is.** It matches the direct rate in every mode
   and still has CPU to spare. sing-box is CPU-bound well below the uplink with REALITY.
2. **Per megabit, tunvless costs about an eighth of sing-box with REALITY**: some 86 Mbit/s per
   busy thread downloading, against about 10.
3. **The encryption is cheap for tunvless and expensive for sing-box.** tunvless downloads cost 90%
   of a thread without encryption and 98% with REALITY. sing-box drops from 45-69 Mbit/s to 24-35
   when REALITY is added. Go's ciphers have no assembly for MIPS and run as plain Go; tunvless
   encrypts with wolfSSL in C.
4. **Uploads cost tunvless far less than downloads** (54% of a thread at 40 Mbit/s with REALITY,
   24% without encryption): uploads gather segments into larger writes to the node, downloads go to
   the TUN device in small pieces.

## What limits tunvless

On a four-stream download without encryption (10 MB/s), `STEER_TUN_STATS=1` shows:

| | |
|---|---|
| loop turns | 1671/s, 12% of the time waiting in epoll |
| reads from the node | 3964/s, 2.6 KB each, 33% of the time |
| writes to the TUN device | 4009/s, 90 µs each (about 36% of the time) |

The loop runs in one thread, and at 84 Mbit/s that thread is nearly full: downloads would stop
growing at about 90 Mbit/s on this router. The time goes into small operations. The data from the
node arrives in WAN-sized pieces and is written to the device almost one read at a time, about
2.6 KB per write, while write offload would take up to 16 KB per write.

If a router with a faster uplink needs more, the first step is larger writes to the TUN device:
let the data of a connection accumulate over a few reads before writing it, so that each write
carries up to 16 KB. More threads are not a quick win, see below.

## Threads

tunvless runs these threads:

| Threads | How many | Setting |
|---|---|---|
| The tunnel loop: the TUN device, every client connection, reads and writes to the nodes | 1 | `STEER_TUN_THREADS` (1-4) |
| Connectors: the TCP, TLS/REALITY and transport handshakes with the nodes | 4, started on the first connection | none (`CONNECTORS` in `src/tunnel/stack.c`) |
| The node pool's health checks, the signal waiter | a few, mostly asleep | none |

**`STEER_TUN_THREADS=N`** (an environment variable, 1 to 4, default 1) opens the TUN device with N
queues (`IFF_MULTI_QUEUE`) and runs a loop thread per queue; the startup log says how many came up
("threads N of M requested"). **It is a knob for experiments, not a performance setting.** The
kernel spreads packets over the queues by a hash of each flow and does not promise that both halves
of a TCP connection land in the same queue. When they do not, the thread that owns the connection
never sees the client's ACKs and stops reading from the node. On a router that gave 12 Mbit/s
against 292 with one queue, and a box that hung under a speed test (see `worker_count` in
`src/tunnel/stack.c`). Not measured on the KN-1810.

Using several cores safely needs the flows tied to threads by something other than the kernel's
hash: handing each packet to the thread that owns its connection, or steering by an eBPF program
(`TUNSETSTEERINGEBPF`, Linux 4.16 and later; the KN-1810 runs 4.9). That is design work, not a
setting.

To set it, or any other `STEER_*` variable, under the Entware init script, export it in
`/opt/etc/tunvless/tunvless.conf`, which the script sources before it starts tunvless:

```sh
export STEER_TUN_STATS=1      # per-second loop statistics in the log
```

## Reproducing

On the server: Xray-core with the nodes above and `"outbounds": [{"protocol": "freedom",
"settings": {"redirect": "127.0.0.1:5201"}}]`, and `iperf3 -s`. Then on the router, with the
tunvless binary and `measure.sh` in `/tmp` (the RAM disk; `/opt` is small) and a file of node links:

```sh
/tmp/tunvless /tmp/nodes.txt -n 0 --no-probe -d tvl0 -r 198.18.0.1/32 &
/tmp/measure.sh "tunvless vision down x4" tunvless --connect-timeout 5000 -c 198.18.0.1 -t 15 -R -P 4
/tmp/measure.sh "tunvless vision up x4"   tunvless --connect-timeout 5000 -c 198.18.0.1 -t 15 -P 4
/tmp/measure.sh "direct down x4"          -        -c <server> -t 15 -R -P 4
```

The router has no `scp` server, `pkill` or `timeout`: copy files with `ssh router 'cat > /tmp/f' < f`
and stop processes with `kill $(pidof name)`.
