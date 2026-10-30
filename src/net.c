/* net.c - a plain TCP connect scan, with an optional banner read.
 *
 * Nothing clever: for each port we open a non-blocking socket, start the
 * connect, and wait for it with select() up to a timeout. A connect that
 * succeeds means the port is open. Then we try to read whatever the service
 * says first (and nudge HTTP ports with a HEAD request). No raw packets, no
 * root needed: this is the same thing a browser or ssh client does. */
#include "net.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>

/* Put `port` into a resolved sockaddr, whichever IP family it is. */
static void set_port(struct sockaddr_storage *ss, int port)
{
    if (ss->ss_family == AF_INET)
        ((struct sockaddr_in *)ss)->sin_port = htons((unsigned short)port);
    else if (ss->ss_family == AF_INET6)
        ((struct sockaddr_in6 *)ss)->sin6_port = htons((unsigned short)port);
}

/* Keep only printable bytes so a banner can never scramble the terminal or
 * the JSON we hand back. Newlines and tabs become spaces. */
static void clean_banner(char *dst, size_t dst_sz, const char *src, ssize_t n)
{
    size_t w = 0;
    for (ssize_t i = 0; i < n && w + 1 < dst_sz; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        if (c >= 32 && c < 127) dst[w++] = (char)c;
    }
    while (w > 0 && dst[w - 1] == ' ') w--;   /* trim trailing spaces */
    dst[w] = '\0';
}

/* Try to read a banner from an already-connected socket. Best effort. */
static void grab_banner(int fd, int port, int timeout_ms, char *out, size_t out_sz)
{
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (port == 80 || port == 8080 || port == 8000) {
        const char *req = "HEAD / HTTP/1.0\r\n\r\n";
        (void)!write(fd, req, strlen(req));
    }

    char buf[512];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n > 0) clean_banner(out, out_sz, buf, n);
}

/* One port: 1 open, 0 not. Fills `banner` when something is read. */
static int try_port(struct sockaddr_storage *ss, socklen_t slen, int port,
                    int timeout_ms, char *banner, size_t banner_sz)
{
    int fd = socket(ss->ss_family, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    set_port(ss, port);
    int opened = 0;
    int r = connect(fd, (struct sockaddr *)ss, slen);
    if (r == 0) {
        opened = 1;                                  /* connected at once */
    } else if (errno == EINPROGRESS) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        if (select(fd + 1, NULL, &wfds, NULL, &tv) > 0) {
            int err = 0;
            socklen_t len = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0)
                opened = 1;
        }
    }

    if (opened) {
        fcntl(fd, F_SETFL, flags);                   /* back to blocking */
        grab_banner(fd, port, timeout_ms, banner, banner_sz);
    }
    close(fd);
    return opened;
}

int ps_scan(const char *host, int from, int to, int timeout_ms,
            ps_result *out, int max, int *count)
{
    *count = 0;
    if (!host || from < 1 || to > 65535 || from > to) return -1;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;

    struct sockaddr_storage ss;
    socklen_t slen = res->ai_addrlen;
    memcpy(&ss, res->ai_addr, slen);
    freeaddrinfo(res);

    for (int p = from; p <= to && *count < max; p++) {
        char banner[PS_BANNER_MAX] = {0};
        if (try_port(&ss, slen, p, timeout_ms, banner, sizeof(banner))) {
            out[*count].port = p;
            out[*count].open = 1;
            memcpy(out[*count].banner, banner, sizeof(banner));
            (*count)++;
        }
    }
    return 0;
}
