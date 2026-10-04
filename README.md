# tunvless

A TUN interface whose TCP and UDP traffic goes to a VLESS server. One small C binary, made for
routers: Entware on aarch64, mipsel and mips (soft-float), and any Linux.

```sh
tunvless 'vless://UUID@server:443?security=reality&sni=example.com&pbk=...&sid=...&flow=xtls-rprx-vision#node' \
    -d tunvless0 -r default
```

That command creates the `tunvless0` device and routes all IPv4 traffic into it. Every connection
that enters the device is carried to the server over VLESS, and the tunnel's own connection to the
server is kept out of it.

## What it speaks

- **VLESS** with a UUID, or the short string Xray derives a UUID from.
- **Security**: `reality` (a ClientHello shaped like Chrome's — the extensions and sizes of uTLS
  `HelloChrome_Auto` — with the X25519MLKEM768 hybrid, ML-DSA-65 `pqv`),
  `tls` (TLS 1.3 with chain and name verification, `pcs`/`vcn` pinning, ECH), and `none`.
- **Transports**: `tcp`, `grpc`, `xhttp`, `ws`, `httpupgrade`.
- **Flow**: `xtls-rprx-vision`, or none.
- **VLESS encryption**: `mlkem768x25519plus` (native/xorpub/random, 1-RTT and 0-RTT).
- **Traffic**: TCP and UDP. UDP over a Vision node goes as Mux.Cool/XUDP, the way Xray's own client
  sends it. ICMP is not forwarded: the client gets "port unreachable", not silence.

TLS 1.3, REALITY and HTTP/2 are tunvless's own code, so the ClientHello can follow Chrome's shape.
wolfSSL supplies only the primitives (hashes, AEADs, X25519, ML-KEM, ML-DSA, X.509) and is linked in
statically.

## The node

The argument is either a `vless://` link or a file containing any of these:

- `vless://` links, one per line, plain or base64 (a subscription);
- an Xray config (`outbounds` with `protocol: vless`);
- a sing-box config (`outbounds` with `type: vless`);
- a Clash/Mihomo YAML (`proxies` with `type: vless`).

Nodes the client cannot serve (an unsupported transport, `allowInsecure` without `--insecure`,
and similar) are skipped, and the reason is printed. `--list` numbers the usable nodes. With a file
and no `--node`, tunvless takes the first node that answers a probe. A probe is a real VLESS request
through the node: it is the only way to tell a REALITY server that accepted us from the decoy site
it shows everyone else.

## Usage

```
tunvless [options] <vless://link | file>

  -n, --node N           use node N of the file (from 0, among usable nodes)
  -l, --list             print the usable nodes and exit
  -p, --probe            check the node (or every node of the file) and exit
      --no-probe         take the first node of the file without checking it
      --insecure         accept allowInsecure nodes; do not verify certificates (security=tls)
      --ca FILE          trusted roots (PEM) for security=tls
  -d, --dev NAME         device name (default tunvless0)
  -a, --addr CIDR        device address (default 198.51.100.1/32)
  -r, --route CIDR       route CIDR into the device; repeatable; "default" = 0.0.0.0/1 + 128.0.0.0/1
  -T, --table N          routing table for --route (default main)
  -m, --mark N           SO_MARK on sockets to the server
  -b, --bind-dev IFACE   send sockets to the server out of IFACE (SO_BINDTODEVICE)
  -t, --timeout S        probe and connect timeout (default 8)
      --silence S        reset a connection whose server stays silent for S seconds (default 20)
      --no-retry         exit instead of retrying when the node does not resolve or answer
```

The device and every route into it disappear when the process exits. SIGINT, SIGTERM and SIGHUP stop
tunvless cleanly, with exit code 0. Exit code 2 means the command line or the node is wrong, so a
restart will not help. Exit code 1 means the tunnel did not come up, or stopped carrying traffic.

### Keeping the server out of the tunnel

If a route into the tunnel also covers the server's address, the tunnel's own connection would
loop into itself. There are three ways to prevent that:

- **Nothing to do (default).** When neither `--mark` nor `--bind-dev` is given, tunvless looks up
  the route each server address takes now and pins it as a host route next to its own, as OpenVPN's
  `redirect-gateway def1` does. It removes that host route when it stops, and leaves one you already
  had alone.
- `--bind-dev wan0` sends the server sockets out of the WAN interface, whatever the routing table
  says.
- `--mark 0x100` marks the server sockets so that your own `ip rule` can route them.

The server's name is resolved once, at startup. After that, new connections never wait on a DNS
query that might itself be routed into the tunnel. To pick up a changed server address, restart
tunvless.

tunvless does not resolve names for the client. To send DNS through the tunnel, route your resolver's
address into it (or use `-r default`).

### Examples

```sh
tunvless --list sub.txt                                # what is in a subscription
tunvless --probe sub.txt                               # which nodes answer, with timings
tunvless sub.txt -r default                            # everything through the first live node
tunvless -n 3 sub.txt -r 10.0.0.0/8 -r 1.1.1.1/32      # only these prefixes, through node 3
tunvless link.txt -r default -b eth3                   # server traffic leaves through eth3
tunvless link.txt -T 100 -r default -m 0x100           # routes in table 100, for your own ip rules
```

## Entware (Keenetic and other routers)

Packages are built by CI with the Entware SDK (GCC 8.4, glibc 2.27) for `aarch64-3.10`,
`mipsel-3.4` and `mips-3.4`. Take the `.ipk` that matches your router (`arch` in
`/opt/etc/opkg.conf`) from the Releases page or from the artifacts of the "Build Entware packages"
workflow, then:

```sh
opkg install ./tunvless_<version>-1_entware_<arch>.ipk
vi /opt/etc/tunvless/tunvless.conf      # ENABLED=yes, NODES=..., ROUTES=...
/opt/etc/init.d/S99tunvless start
logread -e tunvless
```

The package installs `/opt/bin/tunvless`, `/opt/etc/init.d/S99tunvless` and
`/opt/etc/tunvless/tunvless.conf`. It depends on `libpthread`, plus `ca-bundle` for `security=tls`
nodes. The kernel must provide `/dev/net/tun`. If WAN is not up yet at boot, tunvless keeps retrying
on its own until the node resolves and answers.

## Building

```sh
make                 # out/tunvless; fetches wolfSSL (pinned version, sha256-checked) on first run
make test            # unit and crypto tests: no root, no network
sudo make e2e        # the tunnel in network namespaces: TCP with loss, UDP, FIN handling,
                     # receive window, SIGPIPE storm, routes, --bind-dev, --mark, subscriptions
make interop         # against real Xray-core / sing-box (XRAY=..., SINGBOX=...); skipped without
```

Cross-compiling takes the toolchain from the environment:

```sh
make CC=mipsel-openwrt-linux-gnu-gcc AR=mipsel-openwrt-linux-gnu-ar CFLAGS="-Os -msoft-float"
```

CI also builds for aarch64, mipsel and big-endian mips, and runs the unit and crypto tests on each
under qemu.

### Debugging variables

| Variable | Effect |
|---|---|
| `STEER_TUN_TRACE=1` | trace every packet and stream decision |
| `STEER_TUN_STATS=1` | per-second statistics of the tunnel loop |
| `STEER_TUN_SPARES=N` | pre-connected spare sessions to the node (default 4, 0 — off, max 8) |
| `STEER_TUN_THREADS=N` | TUN queues/threads (default 1) |
| `STEER_TUN_RCVWND=N` | receive window ceiling for clients (0 — 65535 without scaling) |
| `STEER_TUN_NOGSO=1`, `STEER_TUN_NOGRO=1`, `STEER_TUN_NORXGSO=1` | turn TUN offloads off |
| `STEER_NOPQ=1` | do not offer X25519MLKEM768 |
| `STEER_CIPHER=...` | force the cipher instead of choosing by AES support |
| `STEER_PQ_TRACE=1`, `STEER_VENC_TRACE=1` | trace post-quantum key exchange / VLESS encryption |

## Layout

```
src/main.c                 command line, node selection, routes, stopping
src/tunnel/                TUN device (tun.c), user-space TCP/UDP stack (stack.c, rtx.c),
                           device and route configuration over netlink (ifcfg.c)
src/proto/vless/           VLESS dialer for the stack, Vision, request header, node parsing
src/proto/transport/       socket, security and transports: tcp, grpc, xhttp, ws, httpupgrade,
                           VLESS encryption
src/proto/tls/             TLS 1.3, REALITY, ECH, certificate verification, HTTP/2
src/lib/                   crypto layer over wolfSSL (scrypto.c), BLAKE3, kernel randomness
build/wolfssl/             wolfSSL fetch, build recipe and options
entware/                   Entware package recipe, init script, config
tests/                     unit, crypto, namespace and interop tests
```

Most comments in the code are in Russian, inherited from where the code comes from.

## Origin and license

tunvless is the TUN + VLESS client of [steer](https://github.com/splify2/steer) 2.0.1, a rule-based
routing core for OpenWrt, cut out to stand alone. The daemon, rule compiler, resolver and other
protocols were removed. The new parts are the command line, netlink device setup, signal handling,
the address pinning, the Entware packaging and a few fixes found on the way. One fix makes
big-endian MIPS work, where wolfSSL had been built with the wrong byte order. Another stops the
stack from answering a client's acknowledgment of the stack's own FIN with a reset.

GPL-3.0, like steer. wolfSSL (GPL-3.0) is fetched at build time; its version and checksum are in
`build/wolfssl/fetch.sh`.
