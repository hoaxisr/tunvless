# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

tunvless: a single static C binary that creates a TUN device and carries its TCP/UDP traffic to a VLESS server. Targets routers (Entware aarch64, mipsel, big-endian mips soft-float) and any Linux. It is the TUN+VLESS client cut out of steer 2.0.x; upstream steer fixes get ported in (see git log "Port steer ...").

## Commands

```sh
make                         # out/tunvless; first run fetches wolfSSL (pinned, sha256-checked) into third_party/
make test                    # unit-test + crypto-test: no root, no network
make unit-test / crypto-test # one half
make out/tests/rtxmatch && out/tests/rtxmatch   # one test: build its target, run the binary
make O=out-asan SANITIZE=address test           # what CI also runs
sudo make e2e                # namespace tunnel tests (iproute2, nftables, python3)
make interop XRAY=... SINGBOX=...               # real Xray-core / sing-box; skipped without them
make CC=mipsel-linux-gnu-gcc AR=mipsel-linux-gnu-ar O=out-mipsel   # cross build
```

Single e2e script: `TUNVLESS=out/tunvless sudo sh tests/failover.sh`.
No separate linter: the build uses `-Wall -Wextra`; keep it warning-free.

## Architecture

Data path: `main.c` (CLI, node parsing/selection, routes, signals) → `tunnel/stack.c` (user-space TCP/UDP stack over the TUN fd, epoll loop threads + connector threads) → dialer table (`tunnel/dialer.h`) → `tunnel/pool.c` (wraps the dialer: N active nodes, health-check probes, failover, `--by` spreading) → `proto/vless/vldial.c` (the one dialer) → `proto/vless/client.c` → transport layer → TLS.

Key boundaries (each documented at length in the header comments; read them before changing a layer):

- **Stack knows no protocol.** Each client flow has an opaque dialer session; all node logic goes through `struct dialer_ops`. The stack has no congestion control and no reassembly (out-of-order client segments are dropped), but does retransmit toward the client (`rtx.c`). `TUNNEL_BUF` drives flow control, not just a buffer size.
- **Transport = two independent tables** (`transport.h`): `security_ops` (none/tls/reality, `trsec.c`) and `transport_ops` (tcp/grpc/xhttp/ws/httpupgrade). Any pair is valid; after the handshake streams share `tr_link_*`. Socket dialing (SO_MARK, SO_BINDTODEVICE) is `trdial.c`.
- **TLS 1.3, REALITY, ECH and HTTP/2 are our own code** (`src/proto/tls/`) so the ClientHello can mimic Chrome (uTLS `HelloChrome_Auto`). wolfSSL supplies only primitives.
- **wolfSSL is visible in exactly one file**, `src/lib/scrypto.c`, compiled with the library's own flags. `scrypto.h` exposes no library types; contexts are fixed-size opaque storage checked by `_Static_assert` against real wolfSSL sizes. Options live in `build/wolfssl/user_settings.h`; growing a struct breaks the build on purpose.
- Logging prefix is `tunvless[warn|info] <area>: ` — consumers filter on it; keep the format.

## Tests

- Tests are plain C programs in `tests/*match.c` etc., using `tests/unit.h` (`check*()`, end with `return unit_done("name");`). Each has its own Makefile target listing exactly which sources it links; adding a test means adding it to `UNIT` or `CRYPTO_TESTS`, a rule, and the list in `.github/workflows/ci.yml` (cross/qemu job).
- Some tests `#include` a `.c` to reach static functions (h2match, tunnelmatch, grpcmatch, vlessmatch); prefer linking the module separately when possible (see `unit.h`).
- Unit tests build without wolfSSL (stub `sc_*` / `tests/trvenc-stub.c`). Crypto tests link a separate test-only wolfSSL (`out/tests/wolfssl`, with cert gen and a TLS server) so the shipped archive never carries those options.
- `hellofreeze` pins the REALITY ClientHello byte-for-byte against `tests/chello-frozen*.h`. Refreeze (`out/tests/hellofreeze --emit > tests/chello-frozen.h`) only together with a capture next to a real browser.
- Under qemu-mips (big-endian) `tunnelmatch` is skipped in CI (qemu TCP_INFO bug), not a real failure.

## Debug env vars

`STEER_TUN_TRACE=1`, `STEER_TUN_STATS=1`, `STEER_TUN_SPARES=N`, `STEER_TUN_THREADS=N`, `STEER_TUN_RCVWND=N`, `STEER_TUN_NOGSO/NOGRO/NORXGSO=1`, `STEER_NOPQ=1`, `STEER_CIPHER=...`, `STEER_PQ_TRACE=1`, `STEER_VENC_TRACE=1` (details in README).

## Packaging

`entware/` holds the Entware SDK recipe, init script `S99tunvless` and `tunvless.conf`; `.github/workflows/build.yml` builds the `.ipk`s. Version comes from `VERSION`.
