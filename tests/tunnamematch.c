/* TUN device name: tun_open must work with exactly the name it was asked for.
 *
 * Nothing looks wrong when this breaks. The kernel silently truncates a name longer than
 * IFNAMSIZ-1 (15 characters) and creates the device under ANOTHER name: xs-abcdefghijklm becomes
 * xs-abcdefghijkl. The queues open, the tunnel runs and the log looks normal, but the address,
 * txqueuelen and routes go to the configured name, which does not exist: "interface up, no
 * traffic".
 *
 * One claim is checked: if the name the kernel returns differs from the one asked for, tun_open
 * FAILS. It fails rather than adopting the kernel's name because firewall rules and routes refer to
 * the device by the configured name.
 *
 * Needs a real device, so CAP_NET_ADMIN and /dev/net/tun: TUNSETIFF is the only place where the
 * kernel reports the name it chose, and there is no way to fake it. Without them the test says it
 * is skipped and exits 0; a silent skip would read as a pass. The device is not persistent (no
 * TUNSETPERSIST) and disappears when its descriptors close, so there is nothing to clean up, but
 * whether it exists is checked in /sys/class/net.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* tun.c is linked, not included: only tun_open is under test. */
#include "../src/tunnel/tun.h"

/* The truncated long name must NOT equal the short one, or the test would check against itself.
 * 15 characters is the limit that must work; 16 is the first that does not fit. */
#define NAME_OK   "xs-namechk-ok15"
#define NAME_LONG "xs-namechk-long6"
#define NAME_CUT  "xs-namechk-long"   /* what the kernel truncates NAME_LONG to */

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-62s %s\n", what, want == got ? "ok" : "FAIL");
    if (want != got) {
        printf("   expected %ld, got %ld\n", want, got);
        fails++;
    }
}

static int dev_exists(const char *name) {
    char path[128];
    struct stat st;
    snprintf(path, sizeof(path), "/sys/class/net/%s", name);
    return stat(path, &st) == 0;
}

static void close_all(struct tun_dev *q, int n) {
    for (int i = 0; i < n; i++) close(q[i].fd);
}

int main(void) {
    struct tun_dev q[4];

    /* Availability probe: the same call the tunnel makes, with a name that surely fits. A failure
     * here means missing privileges or module, not a bug. */
    int probe = tun_open(q, 1, NAME_OK);
    if (probe < 0) {
        printf("SKIPPED: TUNSETIFF unavailable (no /dev/net/tun or CAP_NET_ADMIN)\n");
        printf("The test checks that tun_open fails when the kernel renames the device.\n");
        return 0;
    }
    check("15-character name accepted", 1, probe >= 1);
    check("device with that name created", 1, dev_exists(NAME_OK));
    close_all(q, probe);

    /* The main case: 16 characters. Without the name check tun_open returns the number of
     * queues, a success, and the tunnel goes on with NAME_LONG, which does not exist. */
    int n = tun_open(q, 1, NAME_LONG);
    check("16-character name rejected", 1, n < 0);
    if (n > 0) close_all(q, n);
    check("no device left under the truncated name", 0, dev_exists(NAME_CUT));
    check("no device under the 16-character name", 0, dev_exists(NAME_LONG));

    printf("\n");
    if (fails) {
        printf("FAILED: %d\n", fails);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
