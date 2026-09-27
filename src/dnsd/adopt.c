#include "dnsd_int.h"
#include "tabfmt.h"
#include <poll.h>

/* ---- управляющий сокет резолвера: новый демон забирает живой резолвер ------------------------
 *
 * ЗАЧЕМ. Резолвер — ребёнок демона (src/daemon/supd.c) и прежде выходил, как только закрывалась
 * труба таблицы. Падение демона (kill -9, OOM) уносило поэтому и резолвер, и до перезапуска
 * procd (~5 с) DNS клиентов, завёрнутый на резолвер, не отвечал вовсе. Проверка 1.8 на
 * QEMU-роутере (docs/architecture.md, раздел 5). Теперь EOF трубы — «демона нет» (proxy.c,
 * table_pipe_lost): резолвер отвечает по последней таблице, а новый демон, поднявшись, находит
 * его здесь и забирает.
 *
 * КАК ЗАБИРАЕТ — НОВОЙ ТРУБОЙ ЧЕРЕЗ SCM_RIGHTS, а не таблицей по этому сокету. Демон заводит
 * трубу, как для ребёнка, и отдаёт резолверу её конец чтения; дальше таблица идёт по трубе тем
 * же кодом, что у только что запущенного резолвера (tab_send в supd.c, tabfmt_feed здесь), и
 * смерть демона видна тем же EOF. Таблица по сокету дала бы второй путь с той же обязанностью:
 * свой разбор кадров, свою очередь у демона и свой признак смерти хозяина — и расходиться этим
 * путям было бы с чего. Сокет несёт одну просьбу, и её легко проверить целиком.
 *
 * НАЙТИ — ПО ИМЕНИ: <каталог состояния>/dnsd-ctl.sock (DNSD_CTL_SOCK, tabfmt.h). Pidfile не
 * нужен: подключение и есть проверка «жив ли», а pid собеседника даёт SO_PEERCRED. Сокет
 * отдельный от журнала имён (dlog.c): тот отвечает сразу и ничего не читает, этот ждёт просьбу.
 *
 * ПРОТОКОЛ. Демон подключается и пишет «adopt\n» с дескрипторами в SCM_RIGHTS: первый — конец
 * чтения новой трубы таблицы, второй (необязательный) — его stderr: прежний, унаследованный от
 * умершего демона, ведёт в трубу журнала, которую procd уже закрыл. Ответ — «ok\n» (труба взята)
 * или «busy\n» (у резолвера живой хозяин — его труба открыта; proxy.c, table_pipe_take).
 * Соединение после «ok» остаётся открытым до выхода резолвера: по его закрытию демон узнаёт, что
 * не своего ребёнка больше нет (выход не своего ребёнка waitpid не покажет). Всё прочее, в том
 * числе подключение без просьбы (демон спросил только pid, чтобы погасить), просто закрывается.
 *
 * ВТОРАЯ ПРОСЬБА — «down\n»: её шлёт `steerd down` (src/daemon/apply.c, cmd_down; сам разговор —
 * supd_orphan_down в supd.c). Остановка службы в окне после падения демона — kill -9, и сразу
 * stop, пока procd не поднял его снова (~5 с), — не находила резолвер ничем: stop_service берёт
 * pid экземпляра из ubus, а экземпляра в этот миг нет. Таблицу снимал `steerd down`, а резолвер
 * жил ещё до 60 с на своём порту, дожидаясь демона, которого уже не будет. Ответ — «ok\n», если
 * хозяина нет (труба таблицы закрыта): резолвер выходит штатно, сокет снимает сам, соединение
 * закрывается его выходом; «busy\n» — хозяин жив, и резолвер остаётся: `steer down` руками при
 * живом демоне не должен гасить то, что демон держит и поднял бы заново. Решает сам резолвер, а
 * не спрашивающий: только он знает, открыта ли его труба.
 *
 * ДОСТУП — как у журнала: каталог состояния 0700, сокет 0600 с рождения, собеседник сверяется
 * по SO_PEERCRED — root или тот же uid, что у резолвера (на роутере и телефоне оба — root).
 *
 * ГДЕ ЭТО НЕ ПОМОГАЕТ. На телефоне init при смерти службы гасит всю группу её процессов, и
 * резолвер уходит вместе с демоном; новый демон подключения не находит и поднимает свой резолвер,
 * как прежде. На роутере procd, насколько известно, после падения экземпляра поднимает его снова
 * и прочих процессов не трогает — это проверяется на QEMU-роутере. */
int g_adopt_fd = -1;          /* слушающий */
int g_adopt_conn = -1;        /* принятый, ждёт просьбы */
int g_adopt_owner = -1;       /* соединение нынешнего хозяина (после «ok») */
static char g_adopt_path[PATH_MAX];
static ino_t g_adopt_ino;

#ifndef MSG_CMSG_CLOEXEC
#define MSG_CMSG_CLOEXEC 0x40000000
#endif

void adopt_listen(void) {
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    if ((size_t)snprintf(g_adopt_path, sizeof(g_adopt_path), "%s/" DNSD_CTL_SOCK,
                         steer_state_dir()) >= sizeof(a.sun_path)) {
        fprintf(stderr, "steer[warn] dnsd: путь управляющего сокета слишком длинный — "
                        "новый демон резолвер не заберёт\n");
        g_adopt_path[0] = '\0';
        return;
    }
    memcpy(a.sun_path, g_adopt_path, strlen(g_adopt_path) + 1);   /* длина сверена выше */
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return;
    /* Прежний файл — от упавшего резолвера: живого демон погасил бы до запуска нового. */
    unlink(g_adopt_path);
    mode_t old = umask(0177);
    int rc = bind(fd, (struct sockaddr *)&a, sizeof(a));
    umask(old);
    if (rc != 0 || listen(fd, 2) != 0) {
        fprintf(stderr, "steer[warn] dnsd: управляющий сокет %s: %s — новый демон резолвер не "
                        "заберёт\n", g_adopt_path, strerror(errno));
        close(fd);
        g_adopt_path[0] = '\0';
        return;
    }
    struct stat sb;
    g_adopt_ino = stat(g_adopt_path, &sb) == 0 ? sb.st_ino : 0;
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.ptr = &g_adopt_fd;
    g_adopt_fd = fd;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        close(fd);
        g_adopt_fd = -1;
        unlink(g_adopt_path);
        g_adopt_path[0] = '\0';
    }
}

static void conn_drop(int *slot) {
    if (*slot < 0) return;
    epoll_ctl(g_epfd, EPOLL_CTL_DEL, *slot, NULL);
    close(*slot);
    *slot = -1;
}

void adopt_close(void) {
    conn_drop(&g_adopt_conn);
    conn_drop(&g_adopt_owner);
    if (g_adopt_fd < 0) return;
    close(g_adopt_fd);
    g_adopt_fd = -1;
    struct stat sb;
    if (g_adopt_path[0] && g_adopt_ino && stat(g_adopt_path, &sb) == 0 && sb.st_ino == g_adopt_ino)
        unlink(g_adopt_path);
}

void adopt_accept(void) {
    for (int k = 0; k < 4; k++) {
        int c = accept(g_adopt_fd, NULL, NULL);
        if (c < 0) return;
        fcntl(c, F_SETFD, FD_CLOEXEC);
        fcntl(c, F_SETFL, fcntl(c, F_GETFL) | O_NONBLOCK);
        struct dnsd_ucred uc;
        socklen_t l = sizeof(uc);
        if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &uc, &l) != 0 ||
            (uc.uid != 0 && uc.uid != geteuid())) {
            close(c);
            continue;
        }
        /* Ждёт просьбы одно соединение: демон пишет её сразу после connect, а второе подряд —
         * это уже следующий демон (или прежний, спросивший только pid). */
        conn_drop(&g_adopt_conn);
        struct epoll_event ev = {0};
        ev.events = EPOLLIN;
        ev.data.ptr = &g_adopt_conn;
        if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, c, &ev) != 0) { close(c); continue; }
        g_adopt_conn = c;
    }
}

static void say(int fd, const char *s) {
    ssize_t w = send(fd, s, strlen(s), MSG_NOSIGNAL | MSG_DONTWAIT);
    (void)w;
}

void adopt_conn_event(int *slot) {
    if (*slot < 0) return;
    if (slot == &g_adopt_owner) {
        /* Хозяин ничего не пишет после «ok»: читаемость — это его выход (EOF). */
        char b[64];
        ssize_t m = recv(*slot, b, sizeof(b), MSG_DONTWAIT);
        if (m == 0 || (m < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
            conn_drop(slot);
        return;
    }
    char buf[32];
    union { struct cmsghdr h; char b[CMSG_SPACE(2 * sizeof(int))]; } cm;
    struct iovec iov = { buf, sizeof(buf) - 1 };
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cm.b;
    mh.msg_controllen = sizeof(cm.b);
    ssize_t m = recvmsg(*slot, &mh, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
    int fds[2] = { -1, -1 };
    size_t nfd = 0;
    for (struct cmsghdr *c = m > 0 ? CMSG_FIRSTHDR(&mh) : NULL; c; c = CMSG_NXTHDR(&mh, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
        size_t n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        for (size_t i = 0; i < n; i++) {
            int fd;
            memcpy(&fd, CMSG_DATA(c) + i * sizeof(int), sizeof(int));
            if (nfd < 2) fds[nfd++] = fd;
            else close(fd);
        }
    }
    if (m == 5 && !memcmp(buf, "down\n", 5)) {
        for (size_t i = 0; i < nfd; i++) close(fds[i]);
        if (table_pipe_release() != 0) {
            say(*slot, "busy\n");
            conn_drop(slot);
            return;
        }
        stderr_rescue();
        fprintf(stderr, "steer[info] dnsd: служба остановлена без демона (steerd down) — "
                        "выхожу\n");
        say(*slot, "ok\n");
        /* Соединение остаётся открытым до выхода: его закрытие спрашивающему и есть «вышел». */
        return;
    }
    struct stat sb;
    int ok = m == 6 && !memcmp(buf, "adopt\n", 6) && nfd >= 1 && !(mh.msg_flags & MSG_CTRUNC) &&
             fstat(fds[0], &sb) == 0 && S_ISFIFO(sb.st_mode);
    if (!ok) {
        for (size_t i = 0; i < nfd; i++) close(fds[i]);
        conn_drop(slot);
        return;
    }
    long waited = 0;
    if (table_pipe_take(fds[0], &waited) != 0) {
        close(fds[0]);
        if (fds[1] >= 0) close(fds[1]);
        say(*slot, "busy\n");
        conn_drop(slot);
        return;
    }
    if (fds[1] >= 0) {
        if (dup2(fds[1], 2) < 0)
            fprintf(stderr, "steer[warn] dnsd: stderr нового демона не взят: %s\n", strerror(errno));
        close(fds[1]);
    }
    fprintf(stderr, "steer[info] dnsd: новый демон забрал резолвер (без демона — %ld с)\n", waited);
    say(*slot, "ok\n");
    /* Соединение — теперь хозяина: прежнего (умершего демона) закрыть, это перевести. */
    conn_drop(&g_adopt_owner);
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.ptr = &g_adopt_owner;
    g_adopt_owner = *slot;
    *slot = -1;
    if (epoll_ctl(g_epfd, EPOLL_CTL_MOD, g_adopt_owner, &ev) != 0) {
        close(g_adopt_owner);
        g_adopt_owner = -1;
    }
}

/* ---- stderr резолвера без демона ----------------------------------------------------------------
 *
 * ЗАЧЕМ. stderr резолвера — унаследованный от демона конец трубы журнала procd (`procd_set_param
 * stderr 1`). Пережив демон, резолвер пишет в ту же трубу, и пока procd держит экземпляр, строки
 * доходят до logread. Остановили службу — procd закрывает свой конец, и всё, что резолвер скажет
 * потом («нового демона нет 60 с — выхожу», «служба остановлена без демона»), уходит в EPIPE
 * (SIGPIPE резолвер не слушает) — то есть ровно те строки, по которым видно, куда делся резолвер,
 * в журнал не попадали (проверка долгов на QEMU-роутере, docs/architecture.md, раздел 5).
 *
 * КАК. Запись в трубу без читателя poll отмечает POLLERR — это и проверяется, перед каждой такой
 * строкой, без записи пробы. Сломан — fd 2 становится датаграммным сокетом /dev/log (logd OpenWrt,
 * syslogd busybox): каждая строка stderr — одна запись fprintf, а у небуферизованного stderr — один
 * write, то есть одна датаграмма и одна строка журнала. Метки и уровня в ней нет (syslog даст
 * user.notice), но текст начинается с «steer[…] dnsd:» — по нему её и находят. Нет /dev/log (стенд,
 * телефон — там резолвер и не переживает демон) — /dev/null: писать в сломанную трубу всё равно
 * некуда. Стоит один poll на такую строку, строки эти редки. */
void stderr_rescue(void) {
    struct pollfd p = { 2, POLLOUT, 0 };
    if (poll(&p, 1, 0) != 1 || !(p.revents & (POLLERR | POLLHUP | POLLNVAL))) return;
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    memcpy(a.sun_path, "/dev/log", sizeof("/dev/log"));
    if (fd < 0 || connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        if (fd >= 0) close(fd);
        fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (fd < 0) return;
    }
    /* fd 2 был закрыт вовсе (POLLNVAL) — новый дескриптор и есть 2. */
    if (fd == 2) return;
    dup2(fd, 2);
    close(fd);
}
