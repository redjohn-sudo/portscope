#ifndef PORTSCOPE_NET_H
#define PORTSCOPE_NET_H

#include <stddef.h>

#define PS_BANNER_MAX 256

typedef struct {
    int  port;                     /* port number scanned                    */
    int  open;                     /* 1 if a TCP connection succeeded        */
    char banner[PS_BANNER_MAX];    /* first bytes the service sent, cleaned  */
} ps_result;

/* Resolve `host` once, then try a TCP connect to every port in [from, to]
 * with a per-port timeout in milliseconds. Open ports (and any banner read)
 * are written into `out`, up to `max` entries; `*count` gets how many were
 * written. Returns 0 on success, -1 if the host could not be resolved. */
int ps_scan(const char *host, int from, int to, int timeout_ms,
            ps_result *out, int max, int *count);

#endif /* PORTSCOPE_NET_H */
